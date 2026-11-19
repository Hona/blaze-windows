//! The Windows API the dev runtime calls, declared here with its own `raw-dylib` imports: the
//! standard library's workspace, where blaze builds this crate into every dev executable, has
//! no windows-sys (its copy there is a stub) and no import libraries, so each function names
//! the DLL that exports it and the linker makes the import itself. Names, types and values are
//! windows-sys 0.61's (and so the SDK's), so the code that calls them reads as it did; only
//! what the runtime uses is here.

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

use std::ffi::c_void;

pub(super) type BOOL = i32;
pub(super) type HANDLE = *mut c_void;
pub(super) type HMODULE = *mut c_void;
pub(super) type PSID = *mut c_void;
pub(super) type WELL_KNOWN_SID_TYPE = i32;
pub(super) type TOKEN_INFORMATION_CLASS = i32;

pub(super) const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub(super) const DUPLICATE_SAME_ACCESS: u32 = 2;
pub(super) const INFINITE: u32 = u32::MAX;
pub(super) const WAIT_OBJECT_0: u32 = 0;
pub(super) const WAIT_TIMEOUT: u32 = 258;

pub(super) const ERROR_NO_MORE_FILES: u32 = 18;
pub(super) const ERROR_BROKEN_PIPE: u32 = 109;
pub(super) const ERROR_PIPE_BUSY: u32 = 231;
pub(super) const ERROR_NO_DATA: u32 = 232;
pub(super) const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
pub(super) const ERROR_PIPE_CONNECTED: u32 = 535;
pub(super) const ERROR_OPERATION_ABORTED: u32 = 995;
pub(super) const ERROR_IO_PENDING: u32 = 997;
pub(super) const ERROR_TIMEOUT: u32 = 1460;

pub(super) const UNW_FLAG_NHANDLER: u32 = 0;
pub(super) const TH32CS_SNAPTHREAD: u32 = 4;

pub(super) const MEM_COMMIT: u32 = 0x1000;
pub(super) const MEM_RESERVE: u32 = 0x2000;
pub(super) const MEM_REPLACE_PLACEHOLDER: u32 = 0x4000;
pub(super) const MEM_RELEASE: u32 = 0x8000;
pub(super) const MEM_RESERVE_PLACEHOLDER: u32 = 0x4_0000;
pub(super) const MEM_IMAGE: u32 = 0x100_0000;
pub(super) const MEM_PRESERVE_PLACEHOLDER: u32 = 2;
pub(super) const PAGE_NOACCESS: u32 = 0x01;
pub(super) const PAGE_READONLY: u32 = 0x02;
pub(super) const PAGE_READWRITE: u32 = 0x04;
pub(super) const PAGE_WRITECOPY: u32 = 0x08;
pub(super) const PAGE_EXECUTE_READ: u32 = 0x20;
pub(super) const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub(super) const SEC_COMMIT: u32 = 0x800_0000;

pub(super) const PROCESS_TERMINATE: u32 = 0x0001;
pub(super) const PROCESS_VM_OPERATION: u32 = 0x0008;
pub(super) const PROCESS_VM_READ: u32 = 0x0010;
pub(super) const PROCESS_VM_WRITE: u32 = 0x0020;
pub(super) const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub(super) const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub(super) const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub(super) const PROCESS_SYNCHRONIZE: u32 = 0x10_0000;

pub(super) const ACL_REVISION: u32 = 2;
pub(super) const SECURITY_MAX_SID_SIZE: u32 = 68;
pub(super) const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
pub(super) const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 1;
pub(super) const TOKEN_QUERY: u32 = 8;
pub(super) const TokenUser: TOKEN_INFORMATION_CLASS = 1;
pub(super) const WinLowLabelSid: WELL_KNOWN_SID_TYPE = 66;
pub(super) const WinBuiltinAnyPackageSid: WELL_KNOWN_SID_TYPE = 84;

pub(super) const FILE_READ_DATA: u32 = 0x0001;
pub(super) const FILE_WRITE_DATA: u32 = 0x0002;
pub(super) const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub(super) const SYNCHRONIZE: u32 = 0x10_0000;
pub(super) const FILE_ALL_ACCESS: u32 = 0x1F_01FF;
pub(super) const OPEN_EXISTING: u32 = 3;
pub(super) const PIPE_ACCESS_DUPLEX: u32 = 3;
pub(super) const SECURITY_IDENTIFICATION: u32 = 0x1_0000;
pub(super) const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x8_0000;
pub(super) const SECURITY_SQOS_PRESENT: u32 = 0x10_0000;
pub(super) const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
pub(super) const PIPE_TYPE_BYTE: u32 = 0;
pub(super) const PIPE_READMODE_BYTE: u32 = 0;
pub(super) const PIPE_WAIT: u32 = 0;
pub(super) const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
pub(super) const PIPE_UNLIMITED_INSTANCES: u32 = 255;

/// x86-64's `CONTEXT`, which the runtime only hands to `RtlCaptureContext` and
/// `RtlVirtualUnwind` and reads the instruction pointer of: its bytes, aligned to 16 as those
/// calls store vector registers with aligned stores (windows-sys's is aligned to 8 only).
#[repr(C, align(16))]
pub(super) struct CONTEXT {
    bytes: [u8; 0x4D0],
}

/// Where `Rip` is in [`CONTEXT`]: after six home words, the flags and segments, the debug
/// registers and the sixteen general ones.
const RIP: usize = 0xF8;

const _: () = assert!(size_of::<CONTEXT>() == 0x4D0 && align_of::<CONTEXT>() == 16);

impl CONTEXT {
    /// A context of nothing yet, for `RtlCaptureContext` to fill.
    pub(super) fn zeroed() -> CONTEXT {
        CONTEXT { bytes: [0; 0x4D0] }
    }

    /// The instruction pointer.
    pub(super) fn Rip(&self) -> u64 {
        let mut word = [0; 8];
        word.copy_from_slice(&self.bytes[RIP..RIP + 8]);
        u64::from_ne_bytes(word)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub(super) BeginAddress: u32,
    pub(super) EndAddress: u32,
    pub(super) UnwindInfoAddress: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SYSTEM_INFO {
    pub(super) wProcessorArchitecture: u16,
    pub(super) wReserved: u16,
    pub(super) dwPageSize: u32,
    pub(super) lpMinimumApplicationAddress: *mut c_void,
    pub(super) lpMaximumApplicationAddress: *mut c_void,
    pub(super) dwActiveProcessorMask: usize,
    pub(super) dwNumberOfProcessors: u32,
    pub(super) dwProcessorType: u32,
    pub(super) dwAllocationGranularity: u32,
    pub(super) wProcessorLevel: u16,
    pub(super) wProcessorRevision: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct MEMORY_BASIC_INFORMATION {
    pub(super) BaseAddress: *mut c_void,
    pub(super) AllocationBase: *mut c_void,
    pub(super) AllocationProtect: u32,
    pub(super) PartitionId: u16,
    pub(super) RegionSize: usize,
    pub(super) State: u32,
    pub(super) Protect: u32,
    pub(super) Type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct MEMORY_MAPPED_VIEW_ADDRESS {
    pub(super) Value: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct THREADENTRY32 {
    pub(super) dwSize: u32,
    pub(super) cntUsage: u32,
    pub(super) th32ThreadID: u32,
    pub(super) th32OwnerProcessID: u32,
    pub(super) tpBasePri: i32,
    pub(super) tpDeltaPri: i32,
    pub(super) dwFlags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct OVERLAPPED {
    pub(super) Internal: usize,
    pub(super) InternalHigh: usize,
    pub(super) Offset: u32,
    pub(super) OffsetHigh: u32,
    pub(super) hEvent: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct ACL {
    pub(super) AclRevision: u8,
    pub(super) Sbz1: u8,
    pub(super) AclSize: u16,
    pub(super) AceCount: u16,
    pub(super) Sbz2: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SECURITY_ATTRIBUTES {
    pub(super) nLength: u32,
    pub(super) lpSecurityDescriptor: *mut c_void,
    pub(super) bInheritHandle: BOOL,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SECURITY_DESCRIPTOR {
    pub(super) Revision: u8,
    pub(super) Sbz1: u8,
    pub(super) Control: u16,
    pub(super) Owner: PSID,
    pub(super) Group: PSID,
    pub(super) Sacl: *mut ACL,
    pub(super) Dacl: *mut ACL,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SID_AND_ATTRIBUTES {
    pub(super) Sid: PSID,
    pub(super) Attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TOKEN_USER {
    pub(super) User: SID_AND_ATTRIBUTES,
}

/// All zero, as windows-sys's `Default` for the structures that hold pointers: each is a
/// plain C structure, for which all zero is a value.
macro_rules! zeroed_default {
    ($($ty:ident),*) => {$(
        impl Default for $ty {
            fn default() -> $ty {
                // SAFETY: integers and raw pointers only: all zero is a value.
                unsafe { std::mem::zeroed() }
            }
        }
    )*};
}

zeroed_default!(
    SYSTEM_INFO,
    MEMORY_BASIC_INFORMATION,
    MEMORY_MAPPED_VIEW_ADDRESS,
    OVERLAPPED,
    SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
    SID_AND_ATTRIBUTES,
    TOKEN_USER
);

#[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn GetLastError() -> u32;
    pub(super) fn SetLastError(code: u32);
    pub(super) fn DuplicateHandle(
        source_process: HANDLE,
        source: HANDLE,
        target_process: HANDLE,
        target: *mut HANDLE,
        access: u32,
        inherit: BOOL,
        options: u32,
    ) -> BOOL;
    pub(super) fn FlushInstructionCache(process: HANDLE, at: *const c_void, size: usize) -> BOOL;
    pub(super) fn ReadProcessMemory(
        process: HANDLE,
        at: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> BOOL;
    pub(super) fn WriteProcessMemory(
        process: HANDLE,
        at: *const c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> BOOL;
    pub(super) fn RtlCaptureContext(context: *mut CONTEXT);
    pub(super) fn RtlLookupFunctionEntry(
        pc: u64,
        image: *mut u64,
        history: *mut c_void,
    ) -> *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
    pub(super) fn RtlVirtualUnwind(
        kind: u32,
        image: u64,
        pc: u64,
        function: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
        context: *mut CONTEXT,
        handler_data: *mut *mut c_void,
        frame: *mut u64,
        pointers: *mut c_void,
    ) -> *mut c_void;
    pub(super) fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    pub(super) fn Thread32First(snapshot: HANDLE, entry: *mut THREADENTRY32) -> BOOL;
    pub(super) fn Thread32Next(snapshot: HANDLE, entry: *mut THREADENTRY32) -> BOOL;
    pub(super) fn GetModuleHandleW(name: *const u16) -> HMODULE;
    /// Declared as `live::find` declares it (an address, null for none), so the two agree.
    pub(super) fn GetProcAddress(module: HMODULE, name: *const u8) -> *mut c_void;
    pub(super) fn CreateFileMappingW(
        file: HANDLE,
        attributes: *const SECURITY_ATTRIBUTES,
        protect: u32,
        size_high: u32,
        size_low: u32,
        name: *const u16,
    ) -> HANDLE;
    pub(super) fn UnmapViewOfFile(at: MEMORY_MAPPED_VIEW_ADDRESS) -> BOOL;
    pub(super) fn VirtualFreeEx(process: HANDLE, at: *mut c_void, size: usize, kind: u32) -> BOOL;
    pub(super) fn VirtualProtectEx(
        process: HANDLE,
        at: *const c_void,
        size: usize,
        protect: u32,
        old: *mut u32,
    ) -> BOOL;
    pub(super) fn VirtualQueryEx(
        process: HANDLE,
        at: *const c_void,
        info: *mut MEMORY_BASIC_INFORMATION,
        len: usize,
    ) -> usize;
    pub(super) fn GetSystemInfo(info: *mut SYSTEM_INFO);
    pub(super) fn CreateEventW(
        attributes: *const SECURITY_ATTRIBUTES,
        manual_reset: BOOL,
        initial: BOOL,
        name: *const u16,
    ) -> HANDLE;
    pub(super) fn GetCurrentProcess() -> HANDLE;
    pub(super) fn GetCurrentThreadId() -> u32;
    pub(super) fn OpenProcess(access: u32, inherit: BOOL, pid: u32) -> HANDLE;
    pub(super) fn SetEvent(event: HANDLE) -> BOOL;
    pub(super) fn TerminateProcess(process: HANDLE, code: u32) -> BOOL;
    pub(super) fn WaitForMultipleObjects(
        count: u32,
        handles: *const HANDLE,
        all: BOOL,
        milliseconds: u32,
    ) -> u32;
    pub(super) fn WaitForSingleObject(handle: HANDLE, milliseconds: u32) -> u32;
    pub(super) fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const SECURITY_ATTRIBUTES,
        disposition: u32,
        flags: u32,
        template: HANDLE,
    ) -> HANDLE;
    pub(super) fn ReadFile(
        file: HANDLE,
        buffer: *mut u8,
        len: u32,
        read: *mut u32,
        overlapped: *mut OVERLAPPED,
    ) -> BOOL;
    pub(super) fn WriteFile(
        file: HANDLE,
        buffer: *const u8,
        len: u32,
        written: *mut u32,
        overlapped: *mut OVERLAPPED,
    ) -> BOOL;
    pub(super) fn CancelIoEx(file: HANDLE, overlapped: *const OVERLAPPED) -> BOOL;
    pub(super) fn GetOverlappedResult(
        file: HANDLE,
        overlapped: *const OVERLAPPED,
        transferred: *mut u32,
        wait: BOOL,
    ) -> BOOL;
    pub(super) fn ConnectNamedPipe(pipe: HANDLE, overlapped: *mut OVERLAPPED) -> BOOL;
    pub(super) fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        instances: u32,
        out_buffer: u32,
        in_buffer: u32,
        timeout: u32,
        attributes: *const SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    pub(super) fn GetNamedPipeClientProcessId(pipe: HANDLE, pid: *mut u32) -> BOOL;
    pub(super) fn PeekNamedPipe(
        pipe: HANDLE,
        buffer: *mut c_void,
        len: u32,
        read: *mut u32,
        available: *mut u32,
        left_in_message: *mut u32,
    ) -> BOOL;
    pub(super) fn WaitNamedPipeW(name: *const u16, timeout: u32) -> BOOL;
}

#[link(name = "api-ms-win-core-memory-l1-1-5.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn UnmapViewOfFile2(process: HANDLE, at: MEMORY_MAPPED_VIEW_ADDRESS, flags: u32) -> BOOL;
}

#[link(name = "api-ms-win-core-memory-l1-1-6.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn MapViewOfFile3(
        mapping: HANDLE,
        process: HANDLE,
        at: *const c_void,
        offset: u64,
        size: usize,
        kind: u32,
        protect: u32,
        extended: *mut c_void,
        count: u32,
    ) -> MEMORY_MAPPED_VIEW_ADDRESS;
    pub(super) fn VirtualAlloc2(
        process: HANDLE,
        at: *const c_void,
        size: usize,
        kind: u32,
        protect: u32,
        extended: *mut c_void,
        count: u32,
    ) -> *mut c_void;
}

#[link(name = "api-ms-win-core-synch-l1-2-0.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn WaitOnAddress(
        address: *const c_void,
        compare: *const c_void,
        size: usize,
        milliseconds: u32,
    ) -> BOOL;
    pub(super) fn WakeByAddressAll(address: *const c_void);
}

#[link(name = "bcryptprimitives.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn ProcessPrng(data: *mut u8, len: usize) -> BOOL;
}

#[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    pub(super) fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> BOOL;
    pub(super) fn GetTokenInformation(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> BOOL;
    pub(super) fn CopySid(len: u32, to: PSID, from: PSID) -> BOOL;
    pub(super) fn EqualSid(a: PSID, b: PSID) -> BOOL;
    pub(super) fn CreateWellKnownSid(
        kind: WELL_KNOWN_SID_TYPE,
        domain: PSID,
        sid: PSID,
        len: *mut u32,
    ) -> BOOL;
    pub(super) fn InitializeAcl(acl: *mut ACL, len: u32, revision: u32) -> BOOL;
    pub(super) fn AddAccessAllowedAce(acl: *mut ACL, revision: u32, mask: u32, sid: PSID) -> BOOL;
    pub(super) fn AddMandatoryAce(
        acl: *mut ACL,
        revision: u32,
        flags: u32,
        policy: u32,
        label: PSID,
    ) -> BOOL;
    pub(super) fn InitializeSecurityDescriptor(descriptor: *mut c_void, revision: u32) -> BOOL;
    pub(super) fn SetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: BOOL,
        dacl: *const ACL,
        defaulted: BOOL,
    ) -> BOOL;
    pub(super) fn SetSecurityDescriptorSacl(
        descriptor: *mut c_void,
        present: BOOL,
        sacl: *const ACL,
        defaulted: BOOL,
    ) -> BOOL;
}

#[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    /// psapi's `EnumProcessModules`, which kernel32 exports under this name: the process's
    /// modules in load order, read from its loader's list without taking the loader lock.
    pub(super) fn K32EnumProcessModules(
        process: HANDLE,
        modules: *mut HMODULE,
        bytes: u32,
        needed: *mut u32,
    ) -> BOOL;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layouts the system reads and writes, as the SDK's x64 headers have them (sizes and
    /// the offsets the runtime reads).
    #[test]
    fn the_structures_are_the_sdks_x64_layouts() {
        assert_eq!(size_of::<SYSTEM_INFO>(), 48);
        assert_eq!(std::mem::offset_of!(SYSTEM_INFO, dwAllocationGranularity), 40);
        assert_eq!(size_of::<MEMORY_BASIC_INFORMATION>(), 48);
        assert_eq!(std::mem::offset_of!(MEMORY_BASIC_INFORMATION, RegionSize), 24);
        assert_eq!(std::mem::offset_of!(MEMORY_BASIC_INFORMATION, Type), 40);
        assert_eq!(size_of::<THREADENTRY32>(), 28);
        assert_eq!(size_of::<OVERLAPPED>(), 32);
        assert_eq!(std::mem::offset_of!(OVERLAPPED, hEvent), 24);
        assert_eq!(size_of::<SECURITY_ATTRIBUTES>(), 24);
        assert_eq!(size_of::<SECURITY_DESCRIPTOR>(), 40);
        assert_eq!(size_of::<TOKEN_USER>(), 16);
        assert_eq!(size_of::<ACL>(), 8);
        assert_eq!(size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>(), 12);
    }

    /// A captured context's instruction pointer is in the function that captured it: the
    /// offset [`RIP`] reads is the one the system wrote.
    #[test]
    #[inline(never)]
    fn a_captured_context_holds_its_own_instruction_pointer() {
        let mut context = CONTEXT::zeroed();
        // SAFETY: fills the 16-byte aligned CONTEXT it is given with this thread's registers.
        unsafe { RtlCaptureContext(&mut context) };
        let here =
            a_captured_context_holds_its_own_instruction_pointer as *const () as usize as u64;
        let rip = context.Rip();
        assert!(rip > here && rip < here + 0x1000, "{rip:#x} is not just past {here:#x}");
    }
}
