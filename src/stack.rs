// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::any::Any;

use crate::{
    ebpf::{self, LOCAL_FUNCTION_STACK_SIZE},
    lib::*,
    StackUsageCalculator,
};

#[derive(Debug, Copy, Clone)]
pub struct StackFrame {
    return_address: usize,
    saved_registers: [u64; 4],
    stack_usage: StackUsageType,
}

impl StackFrame {
    /// Create a new stack frame
    pub const fn new() -> Self {
        Self {
            return_address: 0,
            saved_registers: [0; 4],
            stack_usage: StackUsageType::Default,
        }
    }
    /// Save the callee-saved registers
    pub fn save_registers(&mut self, regs: &[u64]) {
        self.saved_registers.copy_from_slice(regs);
    }

    /// Get the callee-saved registers
    pub fn get_registers(&self) -> [u64; 4] {
        self.saved_registers
    }

    /// Save the return address
    pub fn save_return_address(&mut self, address: usize) {
        self.return_address = address;
    }

    /// Get the return address
    pub fn get_return_address(&self) -> usize {
        self.return_address
    }

    /// Set the stack usage
    pub fn set_stack_usage(&mut self, usage: StackUsageType) {
        self.stack_usage = usage;
    }
    /// Get the stack usage
    pub fn get_stack_usage(&self) -> StackUsageType {
        self.stack_usage
    }
}

#[derive(Debug, Copy, Clone)]
pub enum StackUsageType {
    Default,
    Custom(u16),
}

impl StackUsageType {
    pub fn stack_usage(&self) -> u16 {
        match self {
            StackUsageType::Default => LOCAL_FUNCTION_STACK_SIZE,
            StackUsageType::Custom(size) => *size,
        }
    }
}

pub struct StackVerifier {
    calculator: Option<StackUsageCalculator>,
    data: Option<Box<dyn Any>>,
}

impl StackVerifier {
    pub fn new(
        stack_usage_calculator: Option<StackUsageCalculator>,
        data: Option<Box<dyn Any>>,
    ) -> Self {
        Self {
            calculator: stack_usage_calculator,
            data,
        }
    }
    /// Validate the stack usage of a program
    ///
    /// This function checks the stack usage of a program and returns a `StackUsage` object
    /// containing the stack usage for each local function in the program.
    ///
    /// # Returns
    /// - `Ok(StackUsage)` if the stack usage is valid
    /// - `Err(Error)` if the stack usage is invalid
    pub fn stack_validate(&mut self, prog: &[u8]) -> Result<StackUsage, Error> {
        let mut stack_usage = HashMap::new();
        let ty = self.calculate_stack_usage_for_local_func(prog, 0)?;
        stack_usage.insert(0, ty);
        for idx in 0..prog.len() / ebpf::INSN_SIZE {
            let insn = ebpf::get_insn(prog, idx);
            if insn.opc == ebpf::CALL {
                let dst_insn_ptr = idx as isize + 1 + insn.imm as isize;
                let ty = self.calculate_stack_usage_for_local_func(prog, dst_insn_ptr as usize)?;
                stack_usage.insert(dst_insn_ptr as usize, ty);
            }
        }
        Ok(StackUsage(stack_usage))
    }

    /// Calculate the stack usage for a local function
    fn calculate_stack_usage_for_local_func(
        &mut self,
        prog: &[u8],
        pc: usize,
    ) -> Result<StackUsageType, Error> {
        let mut ty = StackUsageType::Default;
        match self.calculator {
            Some(calculator) => {
                ty = StackUsageType::Custom(calculator(prog, pc, self.data.as_mut().unwrap()));
            }
            None => return Ok(ty),
        }
        if ty.stack_usage() % 16 > 0 {
            Err(Error::new(
                ErrorKind::Other,
                format!(
                    "local function (at PC {}) has improperly sized stack use ({})",
                    pc,
                    ty.stack_usage()
                ),
            ))?;
        }
        Ok(ty)
    }
}

pub struct StackUsage(HashMap<usize, StackUsageType>);

impl StackUsage {
    /// Get the stack usage for a local function
    pub fn stack_usage_for_local_func(&self, pc: usize) -> Option<StackUsageType> {
        self.0.get(&pc).cloned()
    }
}
