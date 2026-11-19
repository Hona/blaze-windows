//! A function's unwind information as v2 keeps it ([`Unwind`]): the instructions of its
//! `.eh_frame` entry, apart from where the function is, and its landing pads as read-only
//! data of its own. The linker writes the entries.

use blaze_codegen::{Data, Relocs, Target, Unwind};
use blaze_format::cursor::Reader;
use cranelift_codegen::{
    gimli::{
        self, RunTimeEndian,
        write::{
            Address, CommonInformationEntry, EhFrame, EndianVec, FrameDescriptionEntry, FrameTable,
        },
    },
    isa::TargetIsa,
};

use crate::unwind::{FunctionUnwind, UnwindParts, eh_entry as entry};

/// `unwind` as v2 keeps it, with the data of its landing pads, if it has any. `personality`
/// is the target of the routine that reads them.
pub(crate) fn convert(
    // dyn: cranelift's API takes `&dyn TargetIsa`; its backends are private, one made per process
    isa: &dyn TargetIsa,
    unwind: &FunctionUnwind,
    personality: impl FnOnce() -> Result<Target, String>,
) -> Result<(Unwind, Option<Data>), String> {
    match unwind.v2_parts() {
        UnwindParts::Dwarf { fde, landing_pads } => {
            let common = common(isa)?;
            let fde = common.fde(fde)?;
            // alloc: the landing pads' data, kept with the code; `Data::new` owns its bytes
            let lsda = landing_pads.map(|pads| Data::new(4, pads.to_vec(), Relocs::new()));
            let personality = match lsda {
                Some(_) => Some(personality()?),
                None => None,
            };
            let unwind = Unwind::Dwarf {
                code_align: common.entry.code_align,
                data_align: common.entry.data_align,
                return_address: common.entry.return_address,
                // clone: `Unwind::Dwarf` owns its CIE's few bytes, kept with the code
                cie: common.entry.cie.clone(),
                fde,
                personality,
                lsda: lsda.as_ref().map(|it| it.id),
            };
            Ok((unwind, lsda))
        }
        UnwindParts::Windows { info, landing_pads: None, .. } => {
            // alloc: the function's unwind info, kept with its code; `Unwind::Windows` owns it
            Ok((Unwind::Windows { info: info.to_vec(), handler: None, lsda: None }, None))
        }
        UnwindParts::Windows { info, landing_pads: Some(pads), .. } => {
            let arch = isa.triple().architecture;
            if arch != target_lexicon::Architecture::X86_64 {
                // alloc: the error's message
                return Err(format!(
                    "a Windows function with landing pads on {arch}: blaze names a handler in \
                     x64's UNWIND_INFO alone"
                ));
            }
            let (info, lsda) = windows_handler(info, pads)?;
            let unwind =
                Unwind::Windows { info, handler: Some(personality()?), lsda: Some(lsda.id) };
            Ok((unwind, Some(lsda)))
        }
    }
}

/// `UNWIND_INFO`'s flags of a function whose handler the dispatcher asks while it looks for
/// one (`UNW_FLAG_EHANDLER`: a pad that catches claims the exception) and while it unwinds
/// the frame (`UNW_FLAG_UHANDLER`: a pad that cleans up runs), in the high five bits of its
/// first byte.
const UNW_FLAG_EHANDLER: u8 = 1;
const UNW_FLAG_UHANDLER: u8 = 2;

/// A Windows function's `UNWIND_INFO` with its handler flag, and the data its personality
/// reads ([`crate::unwind::seh::Pads`]): the number of its calls with a landing pad, then
/// theirs, 12 bytes each. The linker writes the handler's RVA after the unwind codes and this
/// data's RVA after it, which `DISPATCHER_CONTEXT::HandlerData` points at.
fn windows_handler(info: &[u8], pads: &[u8]) -> Result<(Vec<u8>, Data), String> {
    let Some(&first) = info.first() else {
        // alloc: the error's message
        return Err("a Windows function with landing pads and no UNWIND_INFO".to_owned());
    };
    if first >> 3 != 0 {
        // alloc: the error's message
        return Err(format!(
            "an UNWIND_INFO with flags {:#x} already: a function with landing pads names its \
             handler alone",
            first >> 3
        ));
    }
    if pads.is_empty() || !pads.len().is_multiple_of(12) {
        // alloc: the error's message
        return Err(format!("{} bytes of landing pads, not 12 a call", pads.len()));
    }
    let count = u32::try_from(pads.len() / 12)
        // alloc: the error's message
        .map_err(|_| format!("{} calls with landing pads", pads.len() / 12))?;
    // alloc: the function's unwind info, kept with its code; `Unwind::Windows` owns it
    let mut info = info.to_vec();
    info[0] |= (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) << 3;
    // alloc: the landing pads' data, kept with the code; `Data::new` owns its bytes
    let mut bytes = Vec::with_capacity(4 + pads.len());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(pads);
    Ok((info, Data::new(4, bytes, Relocs::new())))
}

/// The CIE every function of the process's ISA shares, made and read back once: Cranelift's
/// `create_systemv_cie` depends on the ISA alone.
struct Common {
    /// Its fields as read back, with an FDE of no instructions.
    entry: Entry,
}

impl Common {
    /// The instructions of one function's FDE, as they are written after the shared CIE.
    fn fde(&self, fde: crate::unwind::Fde<'_>) -> Result<Vec<u8>, String> {
        // alloc: the function's FDE, kept with its code
        let mut out = Vec::new();
        fde.write(self.entry.code_align, self.entry.data_align, &mut out)?;
        Ok(out)
    }
}

/// [`Common`] of `isa`'s architecture: Cranelift's CIE reads the architecture and none of the
/// ISA's flags, so every ISA of one architecture (each target's, each feature set's) has one.
// dyn: cranelift's API takes `&dyn TargetIsa`; its backends are private, one made per process
#[expect(
    clippy::disallowed_types,
    reason = "the CIE of each architecture, made once a process: it reads nothing but the architecture"
)]
fn common(isa: &dyn TargetIsa) -> Result<&'static Common, String> {
    static COMMON: [std::sync::OnceLock<Result<Common, String>>; 2] =
        [std::sync::OnceLock::new(), std::sync::OnceLock::new()];
    let slot = match isa.triple().architecture {
        target_lexicon::Architecture::X86_64 => &COMMON[0],
        target_lexicon::Architecture::Aarch64(_) => &COMMON[1],
        // alloc: the error's message
        other => return Err(format!("unwind information for {other}, which has no DWARF CIE")),
    };
    let common = slot.get_or_init(|| {
        let Some(made) = isa.create_systemv_cie() else {
            // alloc: the error's message, once per architecture
            return Err(format!("{} has no DWARF call frame information", isa.triple()));
        };
        let entry = Entry::of(made, FrameDescriptionEntry::new(ANYWHERE, 0))?;
        Ok(Common { entry })
    });
    common.as_ref().map_err(Clone::clone)
}

/// The fields of one CIE and FDE pair, as `.eh_frame` encodes them.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    code_align: u32,
    data_align: i32,
    return_address: u16,
    cie: Vec<u8>,
    fde: Vec<u8>,
}

impl Entry {
    /// Written by gimli, which keeps the instructions of both to itself, and read back.
    fn of(
        cie: CommonInformationEntry,
        fde: gimli::write::FrameDescriptionEntry,
    ) -> Result<Entry, String> {
        let mut table = FrameTable::default();
        let id = table.add_cie(cie);
        table.add_fde(id, fde);
        let mut eh_frame = EhFrame(EndianVec::new(RunTimeEndian::Little));
        // alloc: the error's message; once per process, by `common`
        table.write_eh_frame(&mut eh_frame).map_err(|e| e.to_string())?;
        Entry::read(eh_frame.0.slice())
    }

    /// The CIE and then the FDE of `bytes`, with no augmentation and absolute 8-byte
    /// addresses, as [`Entry::of`] writes them.
    fn read(bytes: &[u8]) -> Result<Entry, String> {
        let mut at = Reader::new(bytes);
        let mut cie = entry(&mut at)?;
        if cie.u32()? != 0 {
            return Err("the first entry is no CIE".to_owned()); // alloc: the error's message
        }
        if cie.u8()? != 1 {
            return Err("a CIE of another version than 1".to_owned()); // alloc: the error's message
        }
        if cie.u8()? != 0 {
            return Err("a CIE with an augmentation".to_owned()); // alloc: the error's message
        }
        // alloc: the error's message
        let code_align = u32::try_from(cie.uleb()?).map_err(|e| e.to_string())?;
        // alloc: the error's message
        let data_align = i32::try_from(cie.sleb()?).map_err(|e| e.to_string())?;
        let return_address = u16::from(cie.u8()?);
        let cie = cie.take_rest().to_vec(); // alloc: once per process, by `common`
        let mut fde = entry(&mut at)?;
        fde.u32()?;
        // Where the function starts and how long it is: the linker's to write.
        fde.skip(16)?;
        let fde = fde.take_rest().to_vec(); // alloc: once per process, by `common`
        if !at.is_done() {
            return Err("more than one CIE and one FDE".to_owned()); // alloc: the error's message
        }
        Ok(Entry { code_align, data_align, return_address, cie, fde })
    }
}

/// Where an FDE for [`Entry::of`] starts: the linker writes the real address.
pub(crate) const ANYWHERE: Address = Address::Constant(0);

#[cfg(test)]
mod tests {
    use cranelift_codegen::gimli::{
        Encoding, Format, Register,
        write::{CallFrameInstruction, CommonInformationEntry, FrameDescriptionEntry},
    };

    use super::*;

    fn x86_cie() -> CommonInformationEntry {
        let encoding = Encoding { address_size: 8, format: Format::Dwarf32, version: 1 };
        let mut cie = CommonInformationEntry::new(encoding, 1, -8, Register(16));
        cie.add_instruction(CallFrameInstruction::Cfa(Register(7), 8));
        cie.add_instruction(CallFrameInstruction::Offset(Register(16), -8));
        cie
    }

    #[test]
    fn reads_back_the_fields_and_instructions() {
        let mut fde = FrameDescriptionEntry::new(ANYWHERE, 32);
        fde.add_instruction(1, CallFrameInstruction::CfaOffset(16));
        fde.add_instruction(1, CallFrameInstruction::Offset(Register(6), -16));
        let entry = Entry::of(x86_cie(), fde).expect("an entry");
        assert_eq!((entry.code_align, entry.data_align, entry.return_address), (1, -8, 16));
        // DW_CFA_def_cfa r7 8, DW_CFA_offset r16 1, padded with DW_CFA_nop.
        assert_eq!(&entry.cie[..5], &[0x0c, 7, 8, 0x80 | 16, 1]);
        assert!(entry.cie[5..].iter().all(|&it| it == 0));
        // DW_CFA_advance_loc 1, DW_CFA_def_cfa_offset 16, DW_CFA_offset r6 2.
        assert_eq!(&entry.fde[..5], &[0x41, 0x0e, 16, 0x80 | 6, 2]);
        assert!(entry.fde[5..].iter().all(|&it| it == 0));
    }

    /// A Windows function with landing pads names the personality as its exception and its
    /// unwind handler (`UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER`), and its handler data is its
    /// own read-only object of the number of its guarded calls and then theirs (a pad that
    /// catches marked), which the linker puts the RVA of after the handler's; one without pads
    /// has neither.
    #[test]
    fn a_windows_function_with_landing_pads_names_its_handler_and_its_pads() {
        let isa = crate::isa_for(crate::Target::of("x86_64-pc-windows-msvc").unwrap()).unwrap();
        // Version 1, a 4-byte prologue, two codes (push rbp; set rbp), frame register rbp.
        let info = vec![1, 4, 2, 5, 4, 0x03, 1, 0x50];
        let mut pads = crate::unwind::seh::Pads::default();
        pads.entered(9..10, 0, false);
        pads.entered(20..21, 0, true);
        let unwind = crate::unwind::FunctionUnwind::from_unwind_info(32, info.clone(), pads);
        let personality = || Ok(Target::Extern("rust_eh_personality".to_owned()));
        let (converted, lsda) = convert(&**isa, &unwind, personality).unwrap();
        let lsda = lsda.expect("the pads' data");
        let Unwind::Windows { info: flagged, handler, lsda: named } = converted else {
            panic!("not Windows unwind info: {converted:?}")
        };
        assert_eq!(flagged[0], 1 | 3 << 3, "version 1, UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER");
        assert_eq!(flagged[1..], info[1..]);
        assert_eq!(handler, Some(Target::Extern("rust_eh_personality".to_owned())));
        assert_eq!(named, Some(lsda.id));
        let words: Vec<u32> =
            lsda.bytes.chunks(4).map(|it| u32::from_le_bytes(it.try_into().unwrap())).collect();
        assert_eq!(words, [2, 9, 10, 0, 20 | 1 << 31, 21, 0], "the second call's pad catches");

        let plain = crate::unwind::FunctionUnwind::from_unwind_info(
            32,
            info.clone(),
            crate::unwind::seh::Pads::default(),
        );
        let refused = || Err("no personality is asked for".to_owned());
        let (converted, lsda) = convert(&**isa, &plain, refused).unwrap();
        assert_eq!(converted, Unwind::Windows { info, handler: None, lsda: None });
        assert!(lsda.is_none());
    }

    #[test]
    fn an_entry_does_not_depend_on_the_length_of_the_code() {
        let entry = |len| Entry::of(x86_cie(), FrameDescriptionEntry::new(ANYWHERE, len));
        assert_eq!(entry(16).expect("an entry"), entry(4096).expect("an entry"));
    }
}
