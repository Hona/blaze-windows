//! blaze's runtime of Windows x64 structured exception handling (blaze's change to `library/`,
//! see `UPSTREAM`): the personality of every function with landing pads, and the two routines
//! its landing pads call.
//!
//! A panic is a C++ exception, thrown by `panic_unwind::seh` with `_CxxThrowException`, as under
//! rustc. rustc's code then has funclets that `__CxxFrameHandler3` calls; blaze's code has
//! landing pads that are blocks of their function, which Windows' unwinder cannot call. So a
//! call with a landing pad is a plain call after which the code looks at a slot of its frame
//! (`ARRIVAL`, the first home slot above the return address), and the function's handler is
//! this personality, both while a handler is looked for and while frames are unwound
//! (`UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER`). Its data is the function's guarded calls
//! (`hir-ty-codegen`'s `unwind::seh::Pads`): `[count: u32]` then `count` times
//! `[after | CATCHES, until, pad: u32]`, offsets from the function's start. A call returns to
//! `after < offset <= until`; with `pad` 0 it returns there with the exception in `ARRIVAL`
//! (Cranelift's code), else it goes on at `pad` with the exception in `rax` (LLVM's). `CATCHES`
//! marks a pad that stops the unwind (`catch_unwind`'s); every other pad cleans up and goes on.
//!
//! The two phases are Windows' own:
//!
//! - **Search.** Only a pad that catches claims a C++ exception: the object is moved to a block
//!   of the heap (what threw it is about to be unwound) and `RtlUnwindEx` unwinds to the pad.
//!   A pad that only cleans up says nothing, so a C++ `catch` above it (Luau's, through mlua's
//!   `extern "C-unwind"` callbacks) is found first, as under `__CxxFrameHandler3`.
//! - **Unwind.** A frame with a cleanup pad unwound past runs it: its handler moves the object
//!   to a block and unwinds to the pad itself (a collided unwind), the pad drops what it holds
//!   and ends in [`resume`], which throws the object again from its own frame, so the search
//!   starts over from there and finds the same handler. A block a search claimed is reused, so
//!   the object is moved once whichever frames run their pads.
//!
//! A C++ object is moved with its type's copy constructor and its source destroyed, unless its
//! type is simple (its copy is its bytes) or it is a Rust panic (whose copy constructor
//! throws, and which is moved as bytes). A foreign C++ exception that reaches `catch_unwind`
//! aborts (`panic_unwind::seh::cleanup` checks the canary), as Rust says. An exception that is
//! no C++ one (an access violation, `longjmp`) is never claimed and runs no pad, as under
//! rustc's `/EHs`-like cleanups.
//!
//! Nothing here may panic: it runs while a panic is in flight, in no frame that has pads.

use core::cell::Cell;
use core::ffi::c_void;
use core::ptr;

/// The exception code of MSVC's C++ runtime, and the magic numbers of its first parameter.
/// The other three are the object, its `ThrowInfo` and the image the latter is relative to.
const CXX_EXCEPTION: u32 = 0xE06D_7363;
const CXX_MAGIC: usize = 0x1993_0520;
const CXX_MAGICS: [usize; 3] = [0x1993_0520, 0x1993_0521, 0x1993_0522];
const EXCEPTION_NONCONTINUABLE: u32 = 1;
const EXCEPTION_UNWINDING: u32 = 0x2;
/// `EXCEPTION_EXIT_UNWIND | EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND`: a frame
/// left with no exception (`longjmp`), the frame unwound to, or an unwind that met another.
const NOTHING_TO_RUN: u32 = 0x4 | 0x20 | 0x40;
/// `EXCEPTION_DISPOSITION::ExceptionContinueSearch`.
const CONTINUE_SEARCH: u32 = 1;
/// The mark of a guarded call whose pad stops the unwind (`unwind::seh::CATCHES`).
const CATCHES: u32 = 1 << 31;
/// The block a pad is entered with: the `ThrowInfo`, the image it is relative to, the
/// object's size, the address the object was thrown at, then the object
/// (`unwind::seh::OBJECT`).
const OBJECT: usize = 32;
/// Where a guarded call of Cranelift's code finds its exception, from its frame pointer
/// (`unwind::seh::ARRIVAL`).
const ARRIVAL: usize = 16;
/// The largest object [`resume`] throws from its own frame: a panic's is three words.
const INLINE_OBJECT: usize = 256;
/// `CatchableType::properties`: a type whose copy is its bytes, and one with a virtual base,
/// whose copy constructor takes a third argument.
const CT_IS_SIMPLE_TYPE: u32 = 1;
const CT_HAS_VIRTUAL_BASE: u32 = 4;
/// The name of a Rust panic's type (`panic_unwind::seh::TYPE_NAME`).
const RUST_PANIC: [u8; 11] = *b"rust_panic\0";

/// The block the last search claimed, which a frame unwound on the way to its pad takes
/// instead of moving the object again.
#[thread_local]
static CLAIMED: Cell<*mut u8> = Cell::new(ptr::null_mut());

/// `EXCEPTION_RECORD` (x64).
#[repr(C)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    _record: *mut ExceptionRecord,
    _address: *mut c_void,
    parameters: u32,
    information: [usize; 15],
}

/// `DISPATCHER_CONTEXT` (x64).
#[repr(C)]
struct DispatcherContext {
    control_pc: usize,
    image_base: usize,
    function_entry: *const RuntimeFunction,
    _establisher_frame: usize,
    _target_ip: usize,
    _context_record: *mut c_void,
    _language_handler: *mut c_void,
    handler_data: *const u32,
    history_table: *mut c_void,
}

/// The size of x64's `CONTEXT`, which is 16-aligned.
const CONTEXT_SIZE: usize = 1232;

/// Room for a `CONTEXT` (x64).
#[repr(C, align(16))]
struct Context([u8; CONTEXT_SIZE]);

/// `RUNTIME_FUNCTION`: image-relative.
#[repr(C)]
struct RuntimeFunction {
    begin: u32,
    _end: u32,
    unwind_info: u32,
}

windows_link::link!("kernel32.dll" "system" fn GetProcessHeap() -> *mut c_void);
windows_link::link!("kernel32.dll" "system" fn HeapAlloc(heap: *mut c_void, flags: u32, bytes: usize) -> *mut c_void);
windows_link::link!("kernel32.dll" "system" fn HeapFree(heap: *mut c_void, flags: u32, block: *mut c_void) -> i32);
// `system`, not `system-unwind`, though it throws: `resume` is a frame of no landing pad,
// and the call of a `-unwind` function is refused under `panic = "abort"`, where this is
// compiled too.
windows_link::link!("kernel32.dll" "system" fn RaiseException(code: u32, flags: u32, count: u32, arguments: *const usize));
windows_link::link!("kernel32.dll" "system" fn RtlUnwindEx(
    target_frame: *mut c_void,
    target_ip: *mut c_void,
    record: *mut ExceptionRecord,
    return_value: *mut c_void,
    context: *mut c_void,
    history: *mut c_void,
));

/// A C++ exception as its record says it: the object, its `ThrowInfo`, the image that is
/// relative to, and the first type it can be caught as (the thrown type itself).
struct Thrown {
    object: *mut u8,
    throw_info: *const u32,
    image: usize,
    /// `CatchableType`: properties, type, displacement (12 bytes), size, copy constructor.
    catchable: *const u32,
    size: usize,
    rust: bool,
}

impl Thrown {
    /// The C++ exception `record` is, if it is one with a `ThrowInfo` (`throw;` has none: it
    /// throws again what a C++ handler holds, which only C++ frames can catch).
    unsafe fn of(record: &ExceptionRecord) -> Option<Thrown> {
        let [magic, object, throw_info, image, ..] = record.information;
        if record.code != CXX_EXCEPTION
            || record.parameters != 4
            || !CXX_MAGICS.contains(&magic)
            || throw_info == 0
        {
            return None;
        }
        let throw_info = throw_info as *const u32;
        // SAFETY: the record is the C++ runtime's, whose `ThrowInfo`, `CatchableTypeArray`,
        // `CatchableType` and `TypeDescriptor` are in the image at `image`.
        unsafe {
            let types = (image + *throw_info.add(3) as usize) as *const u32;
            let catchable = (image + *types.add(1) as usize) as *const u32;
            let size = *catchable.add(5) as usize;
            let descriptor = (image + *catchable.add(1) as usize) as *const u8;
            let rust = *(descriptor.add(16) as *const [u8; 11]) == RUST_PANIC;
            Some(Thrown { object: object as *mut u8, throw_info, image, catchable, size, rust })
        }
    }

    /// Moves the object at `from` to `to`: as bytes for a Rust panic or a simple type, else
    /// with the copy constructor, after which `from` is destroyed.
    unsafe fn move_to(&self, from: *mut u8, to: *mut u8) {
        // SAFETY: `from` holds an object of the thrown type, `to` has room for one, and the
        // constructor and destructor are the image's, called as MSVC's `thiscall` (x64's
        // convention: `this` first).
        unsafe {
            let properties = *self.catchable;
            let copy = *self.catchable.add(6) as usize;
            if self.rust || properties & CT_IS_SIMPLE_TYPE != 0 || copy == 0 {
                ptr::copy_nonoverlapping(from, to, self.size);
                return;
            }
            let copy = self.image + copy;
            if properties & CT_HAS_VIRTUAL_BASE != 0 {
                let copy: unsafe extern "C" fn(*mut u8, *const u8, i32) = core::mem::transmute(copy);
                copy(to, from, 1);
            } else {
                let copy: unsafe extern "C" fn(*mut u8, *const u8) = core::mem::transmute(copy);
                copy(to, from);
            }
            let destroy = *self.throw_info.add(1) as usize;
            if destroy != 0 {
                let destroy: unsafe extern "C" fn(*mut u8) = core::mem::transmute(self.image + destroy);
                destroy(from);
            }
        }
    }

    /// A block of the heap holding the object, the one the last search claimed for this throw
    /// if there is one.
    unsafe fn hold(&self) -> *mut u8 {
        let claimed = CLAIMED.get();
        // SAFETY: a claimed block is one `hold` made, whose fourth word is where its object was
        // thrown; the object is at `self.object` until it is moved.
        unsafe {
            if !claimed.is_null() && *(claimed as *const usize).add(3) == self.object as usize {
                CLAIMED.set(ptr::null_mut());
                return claimed;
            }
            let block = HeapAlloc(GetProcessHeap(), 0, OBJECT + self.size) as *mut u8;
            if block.is_null() {
                // No memory to hold what unwinds: Rust aborts where an allocation fails.
                core::intrinsics::abort_immediate();
            }
            let words = block as *mut usize;
            words.write(self.throw_info as usize);
            words.add(1).write(self.image);
            words.add(2).write(self.size);
            words.add(3).write(self.object as usize);
            self.move_to(self.object, block.add(OBJECT));
            block
        }
    }
}

/// The handler of every function with landing pads ([`self`]), as `EXCEPTION_ROUTINE`.
#[lang = "eh_personality"]
unsafe extern "system" fn rust_eh_personality(
    record: *mut ExceptionRecord,
    frame: *mut u8,
    context: *mut c_void,
    dispatch: *mut DispatcherContext,
) -> u32 {
    let _ = context;
    // SAFETY: the dispatcher calls a handler with its exception record and its dispatcher
    // context, valid for the call; the function entry, its unwind info and its handler data
    // are in the image it names, as the linker wrote them.
    unsafe {
        let record_ref = &*record;
        if record_ref.flags & NOTHING_TO_RUN != 0 {
            return CONTINUE_SEARCH;
        }
        let Some(thrown) = Thrown::of(record_ref) else { return CONTINUE_SEARCH };
        let dispatch = &*dispatch;
        let entry = &*dispatch.function_entry;
        let image = dispatch.image_base;
        let start = image + entry.begin as usize;
        let returned = dispatch.control_pc.wrapping_sub(start);
        let pads = (image + *dispatch.handler_data as usize) as *const u32;
        let mut found = None;
        for at in 0..*pads as usize {
            let call = pads.add(1 + 3 * at);
            let (after, until) = ((*call & !CATCHES) as usize, *call.add(1) as usize);
            if after < returned && returned <= until {
                found = Some((*call & CATCHES != 0, *call.add(2)));
                break;
            }
        }
        let Some((catches, pad)) = found else { return CONTINUE_SEARCH };
        // A search stops at a pad that catches; an unwind runs every pad that cleans up. A
        // frame that catches is unwound past only by an unwind that started below it, of
        // something it would not have claimed.
        let unwinding = record_ref.flags & EXCEPTION_UNWINDING != 0;
        if unwinding == catches {
            return CONTINUE_SEARCH;
        }
        let block = thrown.hold();
        if !unwinding {
            CLAIMED.set(block);
        }
        let target = match pad {
            0 => {
                // The frame the dispatcher names is the frame pointer less what the
                // `UNWIND_INFO` says (`FrameOffset`, in 16 bytes, in its fourth byte's high bits).
                let info = (image + entry.unwind_info as usize) as *const u8;
                let frame_pointer = frame.add(usize::from(*info.add(3) >> 4) * 16);
                (frame_pointer.add(ARRIVAL) as *mut *mut u8).write(block);
                dispatch.control_pc
            }
            pad => start + pad as usize,
        };
        // The unwinder puts `block` in `rax` at the target. It works in a context of its own:
        // the dispatcher's is the outer unwind's while frames are unwound, which a collided
        // unwind copies back to go on from this frame, so a nested unwind working in it would
        // leave this frame the registers of a frame below (its `rbp`, where `ARRIVAL` is).
        let mut scratch = Context([0; CONTEXT_SIZE]);
        RtlUnwindEx(
            frame.cast(),
            target as *mut c_void,
            record,
            block.cast(),
            (&raw mut scratch).cast(),
            dispatch.history_table,
        );
        core::intrinsics::abort_immediate()
    }
}

/// `blaze.seh.resume(exception) -> !`: throws the object a cleanup pad was entered with again,
/// from this frame when it fits, so what catches it has nothing of the block to free.
#[unsafe(export_name = "blaze.seh.resume")]
unsafe extern "C" fn resume(exception: *mut u8) -> ! {
    #[repr(C, align(16))]
    struct Inline([u8; INLINE_OBJECT]);
    // SAFETY: `exception` is a block `Thrown::hold` made, which the pad owns and gives up.
    unsafe {
        if CLAIMED.get() == exception {
            CLAIMED.set(ptr::null_mut());
        }
        let words = exception as *const usize;
        let (throw_info, image, size) = (words.read(), words.add(1).read(), words.add(2).read());
        let record = ExceptionRecord {
            code: CXX_EXCEPTION,
            flags: 0,
            _record: ptr::null_mut(),
            _address: ptr::null_mut(),
            parameters: 4,
            information: [CXX_MAGIC, 0, throw_info, image, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let Some(thrown) = Thrown::of(&record) else { core::intrinsics::abort_immediate() };
        let mut inline = Inline([0; INLINE_OBJECT]);
        let object = match size <= INLINE_OBJECT {
            true => {
                thrown.move_to(exception.add(OBJECT), inline.0.as_mut_ptr());
                HeapFree(GetProcessHeap(), 0, exception.cast());
                inline.0.as_mut_ptr()
            }
            // The block is the object's for as long as it is thrown.
            false => exception.add(OBJECT),
        };
        let arguments = [CXX_MAGIC, object as usize, throw_info, image];
        RaiseException(CXX_EXCEPTION, EXCEPTION_NONCONTINUABLE, 4, arguments.as_ptr());
        core::intrinsics::abort_immediate()
    }
}

/// `blaze.seh.release(exception)`: frees the block a pad that stops the unwind
/// (`catch_unwind`'s) was entered with, once its handler has taken the object.
#[unsafe(export_name = "blaze.seh.release")]
unsafe extern "C" fn release(exception: *mut u8) {
    if CLAIMED.get() == exception {
        CLAIMED.set(ptr::null_mut());
    }
    // SAFETY: `exception` is a block `Thrown::hold` made, which the pad owns and gives up.
    unsafe {
        HeapFree(GetProcessHeap(), 0, exception.cast());
    }
}
