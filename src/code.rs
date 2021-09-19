use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg::*;
use capstone::arch::ArchOperand;
use capstone::{self, Arch, Capstone, Insn, InsnDetail, InsnGroupType, Mode};
use object::{Architecture, File, Object, ObjectSegment};
use std::convert::TryInto;

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
                code: segment.data().unwrap(),
            });
        }
        Some(Code {
            arch,
            mode,
            regions,
        })
    }

    pub(crate) fn calls<F>(&self, begin: u64, end: u64, mut f: F) -> Option<()>
    where
        F: FnMut(u64, u64),
    {
        if let Some(range) = self.range(begin, end) {
            let mut cs =
                Capstone::new_raw(self.arch, self.mode, capstone::NO_EXTRA_MODE, None).ok()?;
            cs.set_detail(true).ok()?;
            for insn in cs.disasm_all(range, begin).ok()?.iter() {
                if let Some(call) = call(self, &cs, &insn) {
                    f(call.from, call.to);
                }
            }
        }
        Some(())
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

fn call(code: &Code, cs: &Capstone, insn: &Insn) -> Option<Call> {
    match code.arch {
        Arch::X86 => call_x86(code, cs, insn),
        _ => None,
    }
}

fn call_x86(code: &Code, cs: &Capstone, insn: &Insn) -> Option<Call> {
    let detail = cs.insn_detail(insn).ok()?;
    if !is_call(&detail) {
        return None;
    }
    let arch_detail = detail.arch_detail();
    for op in arch_detail.operands() {
        if let ArchOperand::X86Operand(op) = op {
            match op.op_type {
                X86OperandType::Imm(imm) => {
                    return Some(Call {
                        from: insn.address(),
                        to: imm as u64,
                    });
                }
                X86OperandType::Mem(op) => {
                    let base = op.base().0 as u32;
                    if base == X86_REG_RIP || base == X86_REG_EIP {
                        let from = insn.address();
                        let mem = (from + insn.bytes().len() as u64).wrapping_add(op.disp() as u64);
                        if base == X86_REG_RIP {
                            if let Some(range) = code.range(mem, mem + 8) {
                                let to = u64::from_le_bytes(range.try_into().unwrap());
                                return Some(Call { from, to });
                            }
                        } else {
                            if let Some(range) = code.range(mem, mem + 8) {
                                let to = u32::from_le_bytes(range.try_into().unwrap()) as u64;
                                return Some(Call { from, to });
                            }
                        }
                    }
                }
                _ => {
                    // TODO: can we do anything with indirect register calls?
                }
            }
        }
    }
    None
}

fn is_call(detail: &InsnDetail) -> bool {
    detail
        .groups()
        .into_iter()
        .any(|group| group.0 as u32 == InsnGroupType::CS_GRP_CALL)
}
