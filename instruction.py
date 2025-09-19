from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Sequence, TYPE_CHECKING

from unicorn import arm64_const

if TYPE_CHECKING:
    from .core import Chomper


INST_ARG_PATTERNS = [
    re.compile(r"(\w+), (\w+), (\w+), (\w+), \[(\w+)]$"),
    re.compile(r"(\w+), (\w+), \[(\w+)]$"),
    re.compile(r"(\w+), \[(\w+)]$"),
    re.compile(r"(\w+), (\w+)$"),
    re.compile(r"(\w+)$"),
]


class BaseInstruction(ABC):
    """Extend instructions not supported by Unicorn."""

    SUPPORTS: Sequence[str]

    def __init__(self, emu: Chomper, code: bytes):
        self.emu = emu

        self._inst = next(self.emu.cs.disasm_lite(code, 0))

        if not any((self._inst[2].startswith(t) for t in self.SUPPORTS)):
            raise ValueError("Unsupported instruction: %s" % self._inst[0])

        # Parse operation registers
        self._regs = []

        if self._inst[3]:
            match = None
            
            for pattern in INST_ARG_PATTERNS:
                match = pattern.match(self._inst[3])
                if match:
                    break

            if not match:
                raise ValueError("Invalid instruction: %s" % self._inst[3])

            for reg in match.groups():
                attr = f"UC_ARM64_REG_{reg.upper()}"
                self._regs.append(getattr(arm64_const, attr))

        # Parse operation bits
        if self._inst[2].endswith("b"):
            self._op_bits = 8
        elif re.search(r"w(\d+)", self._inst[3]):
            self._op_bits = 32
        else:
            self._op_bits = 64

    def read_reg(self, reg_id: int) -> int:
        if reg_id in (arm64_const.UC_ARM64_REG_WZR, arm64_const.UC_ARM64_REG_XZR):
            return 0

        return self.emu.uc.reg_read(reg_id)

    def write_reg(self, reg_id: int, value: int):
        self.emu.uc.reg_write(reg_id, value)

    def exec_next(self):
        next_addr = self.read_reg(self.emu.arch.reg_pc) + 4
        self.write_reg(self.emu.arch.reg_pc, next_addr)

    @abstractmethod
    def execute(self):
        pass


class AutomicInstruction(BaseInstruction):
    """Extend atomic instructions.

    The iOS system libraries will use atomic instructions from ARM v8.1.
    """

    SUPPORTS = ("ldxr", "ldadd", "ldset", "swp", "cas", "casp", "movk")

    def execute(self):
        address = self.read_reg(self._regs[-1])
        # print(f"execute read_int address: 0x{address:x}")
        value = self.emu.read_int(address, self._op_bits // 8)

        result = None

        if self._inst[2].startswith("ldxr"):
            self.write_reg(self._regs[0], value)
        elif self._inst[2].startswith("ldadd"):
            self.write_reg(self._regs[1], value)
            result = value + self.read_reg(self._regs[0])
        elif self._inst[2].startswith("ldset"):
            self.write_reg(self._regs[1], value)
            result = value | self.read_reg(self._regs[0])
        elif self._inst[2].startswith("swp"):
            self.write_reg(self._regs[1], value)
            result = self.read_reg(self._regs[0])
        elif self._inst[2].startswith("casp"):
            # casp指令：比较并交换寄存器对
            # 格式：casp x0, x1, x2, x3, [x23]
            # x0, x1: 期望值对
            # x2, x3: 新值对
            # [x23]: 内存地址
            expected_val1 = self.read_reg(self._regs[0])
            expected_val2 = self.read_reg(self._regs[1])
            
            # 读取内存中的当前值对
            current_val1 = self.emu.read_int(address, self._op_bits // 8)
            current_val2 = self.emu.read_int(address + (self._op_bits // 8), self._op_bits // 8)
            
            # 如果当前值对等于期望值对，则交换
            if current_val1 == expected_val1 and current_val2 == expected_val2:
                new_val1 = self.read_reg(self._regs[2])
                new_val2 = self.read_reg(self._regs[3])
                
                # 写入新值对
                self.emu.write_int(address, new_val1, self._op_bits // 8)
                self.emu.write_int(address + (self._op_bits // 8), new_val2, self._op_bits // 8)
                
                # casp指令成功，不需要设置result，因为已经直接写入内存了
            else:
                # 更新寄存器为当前值
                self.write_reg(self._regs[0], current_val1)
                self.write_reg(self._regs[1], current_val2)
                # casp指令失败，不需要设置result
        elif self._inst[2].startswith("cas"):
            n = self.read_reg(self._regs[0])

            self.write_reg(self._regs[0], value)

            if n == value:
                result = self.read_reg(self._regs[1])
        elif self._inst[2].startswith("movk"):
            # movk指令：Move Wide with Keep
            # 格式：movk x0, #0x1234, lsl #16 或 movk x8, #0xc023 (默认lsl #0)
            # 将16位立即数插入到目标寄存器的指定位置，保持其他位不变
            
            # 获取目标寄存器
            target_reg = self._regs[0]
            
            # 获取当前寄存器值
            current_value = self.read_reg(target_reg)
            
            # 从指令中解析立即数和移位量
            inst_str = self._inst[3]
            
            # 使用正则表达式提取立即数和移位量
            import re
            
            # 首先尝试匹配带lsl的格式：movk x0, #0x1234, lsl #16
            movk_pattern_with_lsl = r"(\w+), #(0x[0-9a-fA-F]+|[0-9]+), lsl #(\d+)"
            match = re.match(movk_pattern_with_lsl, inst_str)
            
            if match:
                reg_name, imm_str, shift_str = match.groups()
                shift = int(shift_str)
            else:
                # 尝试匹配默认格式：movk x8, #0xc023 (默认lsl #0)
                movk_pattern_default = r"(\w+), #(0x[0-9a-fA-F]+|[0-9]+)$"
                match = re.match(movk_pattern_default, inst_str)
                
                if match:
                    reg_name, imm_str = match.groups()
                    shift = 0  # 默认操作低16位
                else:
                    # 如果无法解析指令格式，记录警告并跳过
                    self.emu.logger.warning(f"Unable to parse movk instruction: {inst_str}")
                    self.exec_next()
                    return
            
            # 解析立即数
            if imm_str.startswith('0x'):
                immediate = int(imm_str, 16)
            else:
                immediate = int(imm_str)
            
            # 确保立即数在16位范围内
            immediate &= 0xFFFF
            
            # 计算掩码：清除目标位置的16位
            mask = ~(0xFFFF << shift)
            
            # 计算新值：保持其他位不变，在指定位置插入立即数
            new_value = (current_value & mask) | (immediate << shift)
            
            # 写入目标寄存器
            self.write_reg(target_reg, new_value)
            
            self.emu.logger.debug(f"movk: {reg_name} = 0x{new_value:x} (immediate=0x{immediate:x}, shift={shift})")

        if result is not None:
            result %= 2**self._op_bits
            self.emu.write_int(address, result, self._op_bits // 8)

        self.exec_next()


class PACInstruction(BaseInstruction):
    """Extend PAC instructions.

    The iOS system libraries for the arm64e architecture will use PAC
    instructions.
    """

    SUPPORTS = ("braa", "blraaz", "retab", "paciza")

    def execute(self):
        if self._inst[2] == "braa":
            call_addr = self.read_reg(self._regs[0])
            self.write_reg(self.emu.arch.reg_pc, call_addr)
        elif self._inst[2] == "blraaz":
            call_addr = self.read_reg(self._regs[0])
            ret_addr = self.read_reg(self.emu.arch.reg_pc) + 4
            self.write_reg(self.emu.arch.reg_pc, call_addr)
            self.write_reg(self.emu.arch.reg_lr, ret_addr)
        elif self._inst[2] == "retab":
            ret_addr = self.read_reg(self.emu.arch.reg_lr)
            self.write_reg(self.emu.arch.reg_pc, ret_addr)
        elif self._inst[2] in ("paciza",):
            self.exec_next()


EXTEND_INSTRUCTIONS = [AutomicInstruction, PACInstruction]
