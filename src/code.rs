use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::{self, Arch, Capstone, Insn, InsnDetail, InsnGroupType, Mode};
use object::target_lexicon::Architecture;
use object::{File, Object, ObjectSegment};

#[derive(Debug)]
pub(crate) struct Code<'code> {
    arch: Arch,
    mode: Mode,
    regions: Vec<Region<'code>>,
}

#[derive(Debug)]
struct Region<'code> {
    address: u64,
    code: &'code [u8],
}

#[derive(Debug)]
struct Call {
    pub from: u64,
    pub to: u64,
}

impl<'code> Code<'code> {
    pub(crate) fn new(file: &File<'code>) -> Option<Self> {
        let (arch, mode) = match file.architecture() {
            Architecture::I386 => (Arch::X86, Mode::Mode32),
            Architecture::X86_64 => (Arch::X86, Mode::Mode64),
            _ => return None,
        };
        let mut regions = Vec::new();
        // TODO: handle object files (no segments)
        // TODO: handle relocations
        for segment in file.segments() {
            regions.push(Region {
                address: segment.address(),
                code: segment.data(),
            });
        }
        Some(Code {
            arch,
            mode,
            regions,
        })
    }

    pub(crate) fn calls<F>(&self, begin: u64, end: u64, f: F)
    where
        F: FnMut(u64, u64),
    {
        if let Some(code) = self.range(begin, end) {
            calls(self.arch, self.mode, code, begin, f);
        }
    }

    fn range(&self, begin: u64, end: u64) -> Option<&'code [u8]> {
        for region in &self.regions {
            if begin >= region.address && end <= region.address + region.code.len() as u64 {
                let begin = (begin - region.address) as usize;
                let end = (end - region.address) as usize;
                return Some(&region.code[begin..end]);
            }
        }
        None
    }
}

fn calls<F>(arch: Arch, mode: Mode, code: &[u8], addr: u64, mut f: F) -> Option<()>
where
    F: FnMut(u64, u64),
{
    let mut cs = Capstone::new_raw(arch, mode, capstone::NO_EXTRA_MODE, None).ok()?;
    cs.set_detail(true).ok()?;
    for insn in cs.disasm_all(code, addr).ok()?.iter() {
        if let Some(call) = call(arch, &cs, &insn) {
            f(call.from, call.to);
        }
    }
    Some(())
}

fn call(arch: Arch, cs: &Capstone, insn: &Insn) -> Option<Call> {
    match arch {
        Arch::X86 => call_x86(cs, insn),
        _ => None,
    }
}

fn call_x86(cs: &Capstone, insn: &Insn) -> Option<Call> {
    let detail = cs.insn_detail(insn).ok()?;
    if !is_call(&detail) {
        return None;
    }
    let arch_detail = detail.arch_detail();
    for op in arch_detail.operands() {
        if let ArchOperand::X86Operand(op) = op {
            if let X86OperandType::Imm(imm) = op.op_type {
                return Some(Call {
                    from: insn.address(),
                    to: imm as u64,
                });
            }
        }
    }
    None
}

fn is_call(detail: &InsnDetail) -> bool {
    detail
        .groups()
        .any(|group| group.0 as u32 == InsnGroupType::CS_GRP_CALL)
}
