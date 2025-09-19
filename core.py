import logging
from functools import wraps
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    Uc,
    UcError,
    arm64_const,
    arm_const,
)

from . import const
from .arch import arm_arch, arm64_arch
from .exceptions import EmulatorCrashed, SymbolMissing
from .loader import Module, Symbol
from .instruction import EXTEND_INSTRUCTIONS
from .memory import MemoryManager
from .log import get_logger
from .os import AndroidOs, ANDROID_SYSCALL_MAP, IosOs, IOS_SYSCALL_MAP
from .typing import EndianType, HookContext, HookFuncCallable, HookMemCallable
from .utils import aligned, to_signed

try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64 as CS_ARCH_AARCH64

import os
import struct
import json
import base64

# Mach-O和Fat Header相关常量
FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca  # 大端模式的Fat Magic
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe  # 大端模式
MH_DYLIB = 0x6
CPU_TYPE_ARM64 = 0x0100000c
LC_SEGMENT_64 = 0x19

class Chomper:
    """Lightweight emulation framework for emulating iOS executables and libraries.

    Args:
        arch: The architecture to emulate, support ARM and ARM64.
        mode: The emulation mode.
        os_type: The os type, support Android and iOS.
        logger: The logger to print log.
        endian: Default endian to use.
        enable_vfp: Enable VFP extension of ARM.
        enable_objc: Enable Objective-C runtime of iOS.
        enable_ui_kit: Enable UIKit framework of iOS.
        trace_inst: Print log when any instruction is executed. The emulator will
            call disassembler in real time to output the assembly instructions,
            so this will slow down the emulation.
        trace_symbol_calls: Print log when any symbol is called.
        trace_inst_callback: Custom instruction trace callback.
        user_hook_func: User-defined hook function that will be called after interrupt
            handler setup. This function receives the Chomper instance as parameter
            and can be used to add custom hooks like emu.add_hook().
    """

    os: Union[AndroidOs, IosOs]

    def __init__(
        self,
        arch: int = const.ARCH_ARM64,
        mode: int = const.MODE_ARM,
        os_type: int = const.OS_ANDROID,
        logger: Optional[logging.Logger] = None,
        endian: EndianType = const.LITTLE_ENDIAN,
        rootfs_path: Optional[str] = None,
        enable_vfp: bool = True,
        enable_objc: bool = True,
        enable_ui_kit: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
        trace_inst_callback: Optional[HookFuncCallable] = None,
        user_hook_func: Optional[Callable[["Chomper"], None]] = None,
    ):
        self._setup_arch(arch)

        self.uc = self._create_uc(arch, mode)
        self.cs = self._create_cs(arch, mode)

        self.logger = logger or get_logger(__name__)

        self.os_type = os_type
        self.endian = endian

        self.enable_objc = enable_objc
        self.enable_ui_kit = enable_ui_kit

        self._trace_inst = trace_inst
        self._trace_symbol_calls = trace_symbol_calls

        self._trace_inst_callback = trace_inst_callback

        self.modules: List[Module] = []

        self.hooks: Dict[str, Callable] = {}
        self.syscall_handlers: Dict[int, Callable] = {}

        self.memory_manager = MemoryManager(
            uc=self.uc,
            address=const.HEAP_ADDRESS,
            minimum_pool_size=const.MINIMUM_POOL_SIZE,
        )

        self._setup_emulator(enable_vfp=enable_vfp)
        self._setup_interrupt_handler()
        
        # 调用用户自定义的hook函数
        if user_hook_func:
            user_hook_func(self)

        self._setup_os(os_type, rootfs_path=rootfs_path)

        self.os.initialize()

    @property
    def android_os(self) -> AndroidOs:
        assert isinstance(self.os, AndroidOs)
        return self.os

    @property
    def ios_os(self) -> IosOs:
        assert isinstance(self.os, IosOs)
        return self.os

    def _setup_arch(self, arch: int):
        """Setup architecture."""
        if arch == const.ARCH_ARM:
            self.arch = arm_arch
        elif arch == const.ARCH_ARM64:
            self.arch = arm64_arch
        else:
            raise ValueError("Invalid argument arch")

    def _setup_os(self, os_type: int, **kwargs):
        """Setup operating system."""
        if os_type == const.OS_ANDROID:
            self.os = AndroidOs(self, **kwargs)
        elif os_type == const.OS_IOS:
            self.os = IosOs(self, **kwargs)
        else:
            raise ValueError("Unsupported platform type")

    @staticmethod
    def _create_uc(arch: int, mode: int) -> Uc:
        """Create Unicorn instance."""
        arch = UC_ARCH_ARM if arch == const.ARCH_ARM else UC_ARCH_ARM64
        mode = UC_MODE_THUMB if mode == const.MODE_THUMB else UC_MODE_ARM

        return Uc(arch, mode)

    @staticmethod
    def _create_cs(arch: int, mode: int) -> Cs:
        """Create Capstone instance."""
        arch = CS_ARCH_ARM if arch == const.ARCH_ARM else CS_ARCH_AARCH64
        mode = CS_MODE_THUMB if mode == const.MODE_THUMB else CS_MODE_ARM

        return Cs(arch, mode)

    def _setup_stack(self):
        """Setup stack."""
        stack_addr = const.STACK_ADDRESS + const.STACK_SIZE // 2
        self.uc.mem_map(const.STACK_ADDRESS, const.STACK_SIZE)

        self.uc.reg_write(self.arch.reg_sp, stack_addr)
        self.uc.reg_write(self.arch.reg_fp, stack_addr)

    def _setup_thread_register(self):
        """Setup thread register.

        The thread register store the address of thread local storage (TLS).

        The function only allocates a block of memory to TLS and doesn't really
        initialize.
        """
        self.uc.mem_map(const.TLS_ADDRESS - 1024, const.TLS_SIZE + 1024)

        if self.os_type == const.OS_IOS:
            self.write_u32(const.TLS_ADDRESS + 0x18, 1)

            self.uc.reg_write(arm64_const.UC_ARM64_REG_TPIDRRO_EL0, const.TLS_ADDRESS)
        else:
            if self.arch == arm_arch:
                self.uc.reg_write(
                    arm_const.UC_ARM_REG_CP_REG,
                    (15, 0, 0, 13, 0, 0, 3, const.TLS_ADDRESS),  # type: ignore
                )
            elif self.arch == arm64_arch:
                self.uc.reg_write(arm64_const.UC_ARM64_REG_TPIDR_EL0, const.TLS_ADDRESS)

    def _enable_vfp(self):
        """Enable vfp.

        See details:
        https://github.com/unicorn-engine/unicorn/issues/446
        """
        inst_code = (
            b"\x4f\xf4\x70\x00"  # mov.w r0, #0xf00000
            b"\x01\xee\x50\x0f"  # mcr p15, #0x0, r0, c1, c0, #0x2
            b"\xbf\xf3\x6f\x8f"  # isb sy
            b"\x4f\xf0\x80\x43"  # mov.w r3, #0x40000000
            b"\xe8\xee\x10\x3a"  # vmsr fpexc, r3
        )
        addr = self.create_buffer(1024)

        self.uc.mem_write(addr, inst_code)
        self.uc.emu_start(addr | 1, addr + len(inst_code))

        self.free(addr)

    def _setup_emulator(self, enable_vfp: bool = True):
        """Setup emulator."""
        self._setup_stack()
        self._setup_thread_register()

        if self.arch == arm_arch and enable_vfp:
            self._enable_vfp()

    def _start_emulate(
        self,
        address: int,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
    ) -> int:
        """Start emulate at the specified address."""
        context = self.uc.context_save()
        stop_addr = self.create_buffer(8)

        self.set_args(args, va_list=va_list)

        # Set the value of register LR to the stop address of the emulation,
        # so that when the function returns, it will jump to this address.
        self.uc.reg_write(self.arch.reg_lr, stop_addr)
        self.uc.reg_write(self.arch.reg_pc, address)
        self.uc.reg_write(self.arch.reg_fp, 0)

        try:
            # self.logger.info(f"Start emulate at {self.debug_symbol(address)}")
            # print(f"emu_start address 0x{address:x}")
            self.uc.emu_start(address, stop_addr)
            retval = self.get_retval()
            # print(f"retval: {retval}")
            return retval
        except UcError as e:
            self.crash("Unknown reason", exc=e)
        finally:
            self.uc.context_restore(context)
            self.free(stop_addr)

        # Pass type hints
        return 0

    def find_module(self, name_or_addr: Union[str, int]) -> Optional[Module]:
        """Find module by name or address."""
        for module in self.modules:
            if isinstance(name_or_addr, str):
                if module.name == name_or_addr:
                    return module
            elif isinstance(name_or_addr, int):
                if module.base <= name_or_addr < module.base + module.size:
                    return module

        return None

    def find_symbol(self, symbol_name: str) -> Symbol:
        """Find symbol from loaded modules.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        for module in self.modules:
            for symbol in module.symbols:
                if symbol.name == symbol_name:
                    return symbol

        raise SymbolMissing(f"{symbol_name} not found")

    def debug_symbol(self, address: int) -> str:
        """Format address to `libtest.so!0x1000` or `0x10000`."""
        module = self.find_module(address)

        if module:
            offset = address - module.base

            if module.image_base:
                offset += module.image_base

            return f"{module.name}!{hex(offset)}"

        return hex(address)

    def backtrace(self) -> List[int]:
        """Backtrace call stack."""
        stack = [
            self.uc.reg_read(self.arch.reg_pc),
            self.uc.reg_read(self.arch.reg_lr) - 4,
        ]

        frame = self.uc.reg_read(self.arch.reg_fp)
        limit = 32

        for _ in range(limit - 1):
            address = self.read_pointer(frame + 8)
            frame = self.read_pointer(frame)

            if not frame or not address:
                break

            if address < const.MODULE_ADDRESS:
                continue

            stack.append(address - 4)

        return [address for address in stack if address]

    def log_backtrace(self):
        """Output backtrace log."""
        self.logger.info(
            "Backtrace: %s",
            " <- ".join([self.debug_symbol(t) for t in self.backtrace()]),
        )

    def add_hook(
        self,
        symbol_or_addr: Union[int, str],
        callback: Optional[HookFuncCallable] = None,
        user_data: Optional[dict] = None,
    ) -> int:
        """Add hook to the emulator.

        Args:
            symbol_or_addr: The symbol name or the address to hook. If this is ``str``,
                the function will look up symbol from loaded modules and use its
                address to hook.
            callback: The callback function, same as callback of type ``UC_HOOK_CODE``
                in unicorn.
            user_data: A ``dict`` that contains the data you want to pass to the
                callback function. The ``Chomper`` instance will also be passed in
                as an emulator field.

        Raises:
            SymbolMissingException: If symbol not found.
        """
        if isinstance(symbol_or_addr, int):
            hook_addr = symbol_or_addr
        else:
            symbol = self.find_symbol(symbol_or_addr)
            hook_addr = symbol.address

        if self.arch == arm_arch:
            hook_addr = (hook_addr | 1) - 1

        return self.uc.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=hook_addr,
            end=hook_addr,
            user_data={"emu": self, **(user_data or {})},
        )

    def add_mem_hook(
        self,
        hook_type: int,
        callback: HookMemCallable,
        begin: int = 1,
        end: int = 0,
        user_data: Optional[dict] = None,
    ) -> int:
        """
        Add memory access hook to the emulator.

        Args:
            hook_type: HOOK_MEM_READ or HOOK_MEM_WRITE (defined in chomper.consts)
            callback: Memory hook callback with signature:
                    (uc, access, address, size, value, user_data) -> None
            begin: Start address of memory range to hook. Default is 1.
            end: End address of memory range to hook. Default is 0 (hook all).
            user_data: Optional dictionary passed to callback. `emu` will be added
                automatically.

        Raises:
            ValueError: If hook_type is invalid.
        """
        hook_type_map = {
            const.HOOK_MEM_READ: UC_HOOK_MEM_READ,
            const.HOOK_MEM_WRITE: UC_HOOK_MEM_WRITE,
        }
        uc_hook_type = hook_type_map.get(hook_type)
        if uc_hook_type is None:
            raise ValueError("Invalid argument hook_type")

        return self.uc.hook_add(
            uc_hook_type,
            callback,
            begin=begin,
            end=end,
            user_data={"emu": self, **(user_data or {})},
        )

    def add_interceptor(
        self,
        symbol_or_addr: Union[int, str],
        callback: HookFuncCallable,
        user_data: Optional[dict] = None,
    ) -> int:
        """Add interceptor to the emulator."""

        @wraps(callback)
        def decorator(uc: Uc, address: int, size: int, user_data_: HookContext):
            emu = user_data_["emu"]
            address = emu.uc.reg_read(emu.arch.reg_pc)

            retval = callback(uc, address, size, user_data_)

            if isinstance(retval, int):
                emu.set_retval(retval)

            if address == emu.uc.reg_read(emu.arch.reg_pc):
                emu.uc.reg_write(emu.arch.reg_pc, emu.uc.reg_read(emu.arch.reg_lr))

        print(f"add_interceptor symbol_or_addr: 0x{symbol_or_addr:x}")
        return self.add_hook(symbol_or_addr, decorator, user_data)

    def del_hook(self, handle: int):
        """Delete hook."""
        self.uc.hook_del(handle)

    def crash(self, message: str, exc: Optional[Exception] = None):
        """Raise an emulator crashed exception and output debugging info.

        Raises:
            EmulatorCrashedException:
        """
        address = self.uc.reg_read(self.arch.reg_pc)
        self.logger.error(
            "Emulator crashed from: %s",
            " <- ".join([self.debug_symbol(t) for t in self.backtrace()]),
        )

        raise EmulatorCrashed(f"{message} at {self.debug_symbol(address)}") from exc

    def trace_symbol_call_callback(
        self, uc: Uc, address: int, size: int, user_data: dict
    ):
        """Trace symbol call."""
        symbol = user_data["symbol"]
        ret_addr = self.uc.reg_read(self.arch.reg_lr)

        if ret_addr:
            self.logger.info(
                f'Symbol "{symbol.name}" called from {self.debug_symbol(ret_addr)}'
            )
        else:
            self.logger.info(f'Symbol "{symbol.name}" called')

    def trace_inst_callback(self, uc: Uc, address: int, size: int, user_data: HookContext):
        """Trace instruction."""
        if self._trace_inst_callback:
            self._trace_inst_callback(uc, address, size, user_data)
        else:
            inst = next(self.cs.disasm_lite(uc.mem_read(address, size), address))
            self.logger.info(
                f"Trace at {self.debug_symbol(address)}: {inst[-2]} {inst[-1]}"
            )

    @staticmethod
    def missing_symbol_required_callback(*args):
        """Raise an exception with information of missing symbol."""
        user_data = args[-1]
        symbol_name = user_data["symbol_name"]

        raise EmulatorCrashed(
            f"Missing symbol '{symbol_name}' is required, "
            f"you should load the library that contains it."
        )

    def _setup_interrupt_handler(self):
        """Setup interrupt handler."""
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_callback)

    def _interrupt_callback(self, uc: Uc, intno: int, user_data: dict):
        """Handle interrupt from emulators.

        There are currently two types of interrupts that need to be actively handled,
        system calls and some unsupported instructions.
        """
        if intno == 2:
            self._dispatch_syscall()
            return
        elif intno in (1, 4):
            # Handle cpu exceptions
            address = self.uc.reg_read(self.arch.reg_pc)
            code = uc.mem_read(address, 4)

            for extend_inst in EXTEND_INSTRUCTIONS:
                try:
                    extend_inst(self, code).execute()
                    return
                except ValueError:
                    pass

        self.crash(f"Unhandled interruption {intno}")

    def _dispatch_syscall(self):
        """Dispatch system calls to the registered handlers of the OS."""
        syscall_no = None
        syscall_name = None

        if self.os_type == const.OS_IOS:
            syscall_no = to_signed(self.uc.reg_read(arm64_const.UC_ARM64_REG_W16), 4)
            syscall_name = (
                f"'{IOS_SYSCALL_MAP[syscall_no]}'"
                if syscall_no in IOS_SYSCALL_MAP
                else hex(syscall_no)
            )
        elif self.os_type == const.OS_ANDROID and self.arch == arm64_arch:
            syscall_no = to_signed(self.uc.reg_read(arm64_const.UC_ARM64_REG_W8), 4)
            syscall_name = (
                f"'{ANDROID_SYSCALL_MAP[syscall_no]}'"
                if syscall_no in ANDROID_SYSCALL_MAP
                else hex(syscall_no)
            )

        if syscall_no and syscall_name:
            from_ = self.debug_symbol(self.uc.reg_read(self.arch.reg_pc))
            self.logger.info(f"System call {syscall_name} invoked from {from_}")

            syscall_handler = self.syscall_handlers.get(syscall_no)

            if syscall_handler:
                # print(f"syscall_handler: {syscall_handler} syscall_no: 0x{syscall_no:x}")
                result = syscall_handler(self)
                if result is not None:
                    self.set_retval(result)
                return

        if syscall_name is not None:
            self.crash(f"Unhandled system call {syscall_name}")
        else:
            self.crash("Unhandled system call")

    def add_inst_trace(self, module: Module):
        """Add instruction trace for the module."""
        self.uc.hook_add(
            UC_HOOK_CODE,
            self.trace_inst_callback,
            begin=module.base,
            end=module.base + module.size,
            user_data={"emu": self},
        )

    def exec_init_array(self, init_array: List[int]):
        """Execute initialization functions."""
        for init_func in init_array:
            if not init_func:
                continue

            try:
                self.logger.info(
                    f"Execute initialization function {self.debug_symbol(init_func)}"
                )
                self.call_address(init_func)
            except Exception as e:
                self.logger.warning(
                    f"Execute {self.debug_symbol(init_func)} failed: {repr(e)}"
                )

    def find_arm64_slice_in_fat(self, file_path:str):
        """从Fat文件中找到arm64架构的切片偏移量，或者处理非fat格式的Mach-O arm64文件"""
        try:
            with open(file_path, 'rb') as f:
                # 读取Magic判断文件类型
                magic = struct.unpack('I', f.read(4))[0]
                
                # 如果是Fat文件
                if magic in (FAT_MAGIC, FAT_CIGAM):
                    # 确定字节序
                    endian = '<' if magic == FAT_MAGIC else '>'

                    # 读取Fat Header: magic(4), nfat_arch(4)
                    f.seek(0)
                    fat_header = struct.unpack(f'{endian}II', f.read(8))
                    nfat_arch = fat_header[1]  # 架构数量

                    # 遍历每个架构切片
                    for _ in range(nfat_arch):
                        # 读取fat_arch结构
                        arch_format = f'{endian}IIIII'
                        arch_info = struct.unpack(arch_format, f.read(20))
                        cputype, _, offset, _, _ = arch_info

                        # 检查是否为arm64架构
                        if cputype == CPU_TYPE_ARM64:
                            return offset  # 返回该切片在文件中的偏移量

                    # 未找到arm64切片
                    return None
                
                # 如果是Mach-O 64-bit文件
                elif magic in (MH_MAGIC_64, MH_CIGAM_64):
                    # 确定字节序
                    endian = '<' if magic == MH_MAGIC_64 else '>'
                    
                    # 读取mach_header_64的cputype字段
                    f.seek(4)  # 跳过magic，定位到cputype
                    cputype = struct.unpack(f'{endian}i', f.read(4))[0]
                    
                    # 检查是否为arm64架构
                    if cputype == CPU_TYPE_ARM64:
                        return 0  # 非fat格式的arm64文件，从文件开始处读取
                    else:
                        return None  # 不是arm64架构
                
                else:
                    return None  # 既不是Fat文件也不是Mach-O 64-bit文件

        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {e}")
            return None

    def get_all_segments_64_info(self, file_path:str, slice_offset:int = None):
        # 非Fat文件，直接返回0
        if slice_offset == 0:
            return 0
        """获取所有LC_SEGMENT_64的vm address，返回最小的vm address作为macho起始地址"""
        try:
            with open(file_path, 'rb') as f:
                # 定位到正确的位置(文件开始或Fat切片开始)
                start_offset = slice_offset if slice_offset is not None else 0
                f.seek(start_offset)

                # 读取magic number确定字节序
                magic = struct.unpack('I', f.read(4))[0]
                if magic not in (MH_MAGIC_64, MH_CIGAM_64):
                    return None

                endian = '<' if magic == MH_MAGIC_64 else '>'

                # 读取mach_header_64
                f.seek(start_offset)
                # 包含reserved字段的完整64位头部格式
                header_format = f'{endian}IiiiiIII'  # 8个字段
                header_size = struct.calcsize(header_format)
                header = struct.unpack(header_format, f.read(header_size))

                # 解析头部信息（8个字段）
                magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = header

                # 计算load commands的实际范围
                load_commands_start = start_offset + header_size
                load_commands_end = load_commands_start + sizeofcmds

                # 移动到load commands开始位置
                f.seek(load_commands_start)

                min_vm_addr = None
                current_position = load_commands_start

                # 遍历所有load commands，增加边界检查
                for _ in range(ncmds):
                    # 检查是否超出load commands总大小范围
                    if current_position + 8 > load_commands_end:
                        break  # 防止越界

                    # 读取命令头部 (cmd和cmdsize)
                    cmd_header = struct.unpack(f'{endian}II', f.read(8))
                    cmd, cmdsize = cmd_header

                    # 检查cmdsize是否合理
                    if cmdsize < 8 or current_position + cmdsize > load_commands_end:
                        break  # 无效的命令大小，防止越界

                    # 处理LC_SEGMENT_64类型的命令
                    if cmd == LC_SEGMENT_64:
                        # 回退到段命令开始处
                        f.seek(current_position)

                        # 解析segment_command_64结构
                        # 结构: cmd(4), cmdsize(4), segname(16), vmaddr(8), vmsize(8), fileoff(8), filesize(8), ...
                        seg_format = f'{endian}II16sQQQQ'
                        seg_format_size = struct.calcsize(seg_format)

                        # 确保有足够的字节可以读取
                        if cmdsize >= seg_format_size:
                            seg_data = struct.unpack(seg_format, f.read(seg_format_size))

                            # 提取段名称（去除末尾的空字符）
                            segname = seg_data[2].decode('utf-8').strip('\x00')
                            vm_addr = seg_data[3]  # vm addr
                            vm_size = seg_data[4]  # vm size

                            print(f"Found segment '{segname}' with vm_addr: 0x{vm_addr:x}, vm_size: 0x{vm_size:x}")
                            
                            # 排除__PAGEZERO段，更新最小的vm address
                            if segname != "__PAGEZERO" and (min_vm_addr is None or vm_addr < min_vm_addr):
                                min_vm_addr = vm_addr

                    # 移动到下一个命令
                    current_position += cmdsize
                    f.seek(current_position)

                # 返回找到的最小vm address
                if min_vm_addr is not None:
                    print(f"Minimum vm address found: 0x{min_vm_addr:x}")
                    return min_vm_addr
                else:
                    print("No LC_SEGMENT_64 commands found")
                    return None

        except Exception as e:
            print(f"解析文件 {file_path} 时出错: {e}")
            return None
    
    def dump_memory_with_width(self, addr: int, width: int):
        """
        Python版本的dumpMemeryWithWidth函数
        根据OC代码：NS_INLINE void dumpMemeryWithWidth(int64_t* addr,int width)
        
        Args:
            addr: 内存地址
            width: 要dump的内存宽度（以64位为单位）
        """
        print("-------------------------------------------")
        for i in range(width):
            try:
                # 读取64位值
                value = self.os.emu.read_u64(addr + i * 8)
                print(f"memory dump >{addr + i * 8:016x}:{value:016x}<")
            except Exception as e:
                print(f"memory dump >{addr + i * 8:016x}:<error reading memory: {e}>")
                
    def hook_mem_read_unmapped(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
              f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
              f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} "
              f"x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} "
              f"x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} "
              f"x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x} "
              f"x16 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X16')):x} "
              f"x17 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X17')):x} "
              f"x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} "
              f"x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} "
              f"x21 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X21')):x} "
              f"x22 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X22')):x} "
              f"x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} "
              f"x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} "
              f"x25 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X25')):x} "
              f"x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} "
              f"x27 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X27')):x} "
              f"x28 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X28')):x} "
              f"x29 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X29')):x} "
              f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        print(f"0x1D6101370:0x{int.from_bytes(uc.mem_read(0x1D6101370, 8), byteorder=self.endian):x}")
    
    def print_registers_and_backtrace(self, uc, address: int, size: int, user_data: dict):
        print(f"[print_registers_and_backtrace] 地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
              f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
              f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} "
              f"x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} "
              f"x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} "
              f"x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x} "
              f"x16 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X16')):x} "
              f"x17 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X17')):x} "
              f"x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} "
              f"x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} "
              f"x21 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X21')):x} "
              f"x22 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X22')):x} "
              f"x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} "
              f"x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} "
              f"x25 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X25')):x} "
              f"x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} "
              f"x27 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X27')):x} "
              f"x28 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X28')):x} "
              f"x29 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X29')):x} "
              f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.log_backtrace()

    def hook_mem_read_unmapped_1800B5FBC(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
              f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
              f"x2 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
              f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}"
              )
        self.log_backtrace()
        
    def hook_mem_read_unmapped_1800B3524(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"0xFFFFFC023:0x{self.os.emu.read_u64(0xFFFFFC023):x}")
        print(f"x16 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X16')):x}")
        
    def hook_mem_read_unmapped_1800A12D0(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        
    def hook_mem_read_unmapped_1800A12E4(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X8'), 0x400e0e01)
    
    def load_module(
        self,
        module_file: str,
        exec_init_array: bool = True,
        exec_objc_init: bool = True,
        trace_inst: bool = False,
        trace_symbol_calls: bool = False,
        need_map_mem: bool = False,
        specify_module_base: Optional[int] = None,
        app_framework: Optional[bool] = False,
        is_user_lib: Optional[bool] = False,
    ) -> Module:
        """Load executable file from path.

        Args:
            module_file: The path of file to be loaded.
            exec_init_array: Execute initialization functions recorded in the section
                `.init_array` after the module loaded.
            exec_objc_init: Execute `_objc_init` function after the module loaded.
            trace_inst: Output log when the instructions in this module are executed.
                The emulator will call disassembler in real time to display the
                assembly instructions, so this will slow down the emulation.
            trace_symbol_calls: Output log when the symbols in this module are called.
        """
        if isinstance(self.os, IosOs):
            self.os.set_main_executable(module_file)

        slice_offset = self.find_arm64_slice_in_fat(module_file)
        print(f"load_module slice_offset: 0x{slice_offset:x}")
        module_base = self.get_all_segments_64_info(module_file, slice_offset)
        print(f"load_module 1 module_base: 0x{module_base:x}")
        if not module_base:
            # module_base = const.MODULE_ADDRESS
            module_base = 0
            # print(f"load_module 2 module_base: 0x{module_base:x}")
        # if not self.modules:clea
        #     module_base = const.MODULE_ADDRESS
        # else:
        #     prev = self.modules[-1]
        #     module_base = aligned(prev.base + prev.size, 1024 * 1024)

        if specify_module_base:
            module_base = specify_module_base

        module = self.os.loader.load(
            module_base=module_base,
            module_file=module_file,
            trace_symbol_calls=trace_symbol_calls or self._trace_symbol_calls,
            map_mem=need_map_mem,
            app_framework=app_framework,
        )

        if is_user_lib:
            # 存储 dyld 信息到字典中
            image_index = len(self.os._dyld_image_info)
            print(f"存储 dyld 信息到字典中 module_file: {module_file} module.base: {module.base} image_index: {image_index}")
            self.os._dyld_image_info[image_index] = {
                'dli_fname': module_file,  # 模块文件路径
                'dli_fbase': module.base,  # 模块基地址
                'dli_sname': '__dso_handle',  # 固定符号名
                'dli_saddr': module.base,  # 符号地址（使用基地址）
                'module_name': module_file,  # 模块名称（用于调试）
            }

        self.modules.append(module)
        
        # print(f"0x1D6101370:0x{int.from_bytes(self.os.emu.uc.mem_read(0x1D6101370, 8), byteorder=self.endian):x}")

        if module_file.endswith("/Taobao4iPhone"):
            # # self.os.emu.add_hook(0x18007F0D4, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x1800B3524, self.hook_mem_read_unmapped_1800B3524)
            # # self.os.emu.add_hook(0x1800B601C, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x1800B5FE4, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x1800B5FE8, self.hook_mem_read_unmapped)
            
            # # self.os.emu.add_hook(0x1000082B8, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x106E640EC, self.hook_mem_read_unmapped)

            # # # self.os.emu.add_hook(0x193E1A49C, self.hook_mem_read_unmapped)
            # # # self.os.emu.add_hook(0x193E1A4F8, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x193E1A494, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x193E1A540, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x193E1A460, self.hook_mem_read_unmapped)

            # self.os.emu.add_hook(0x1800B5FBC, self.hook_mem_read_unmapped_1800B5FBC)
            
            # self.os.emu.add_hook(0x10000FE5C, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x10000FE60, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x10000FE64, self.hook_mem_read_unmapped)
            # # self.os.emu.add_hook(0x10000FE68, self.hook_mem_read_unmapped)

            # # self.os.emu.add_hook(0x106E4C194, self.hook_mem_read_unmapped)
           
            # # self.os.emu.add_hook(0x18161AA44, self.hook_mem_read_unmapped)
           
            # # # self.os.emu.add_hook(0x1800A12D0, self.hook_mem_read_unmapped_1800A12D0)
            # # self.os.emu.add_hook(0x1800A12E4, self.hook_mem_read_unmapped_1800A12E4)

            # # not passed
            # # self.os.emu.add_hook(0x1C6ABB7F0, self.hook_mem_read_unmapped)
            # # passed
            # # self.os.emu.add_hook(0x1C6ABCD2C, self.hook_mem_read_unmapped) 


            # self.os.emu.add_hook(0x1028149F0, self.print_registers_and_backtrace)
            # self.os.emu.add_hook(0x1003D338C, self.print_registers_and_backtrace)
            # self.os.emu.add_hook(0x100F78BE0, self.print_registers_and_backtrace)
            # self.os.emu.add_hook(0x100A2E4B0, self.print_registers_and_backtrace)
            # self.os.emu.add_hook(0x100F78AE4, self.print_registers_and_backtrace)
            
           

        # Trace instructions
        if trace_inst or self._trace_inst:
            self.add_inst_trace(module)

        if exec_objc_init and isinstance(self.os, IosOs):
            print(f"call init_objc in load_module module: {module.name}")
            self.os.init_objc(module)

        if module_file.endswith("/Taobao4iPhone"):
            print(f"0x107391060:0x{self.os.emu.read_u64(0x107391060):x}")
            self.os.emu.write_u64(0x10A8BED08, 0x10285FFCC)

        if exec_init_array and module.init_array:
            self.exec_init_array(module.init_array)

        return module

    def _get_arg_container(self, index: int) -> Tuple[bool, int]:
        """Get the register or address where the specified argument is stored.

        On arch ARM, the first four parameters are stored in the register R0-R3, and
        the rest are stored on the stack. On arch ARM64, the first eight parameters
        are stored in the register X0-X7, and the rest are stored on the stack.

        Returns:
            A ``tuple`` contains a ``bool`` and an ``int``, the first member means
            whether the returned is a register and the second is the actual register
            or address.
        """
        if index >= len(self.arch.reg_args):
            # Read address from stack.
            offset = (index - len(self.arch.reg_args)) * self.arch.addr_size
            address = self.uc.reg_read(self.arch.reg_sp) + offset
            return False, address

        return True, self.arch.reg_args[index]

    def get_arg(self, index: int) -> int:
        """Get argument with the specified index."""
        is_reg, reg_or_addr = self._get_arg_container(index)

        if is_reg:
            return self.uc.reg_read(reg_or_addr)
        else:
            return self.read_int(reg_or_addr, self.arch.addr_size)

    def set_arg(self, index: int, value: int):
        """Set argument with the specified index."""
        is_reg, reg_or_addr = self._get_arg_container(index)

        if is_reg:
            self.uc.reg_write(reg_or_addr, value)
        else:
            self.write_int(reg_or_addr, value, self.arch.addr_size)

    def set_args(self, args: Sequence[int], va_list: Optional[Sequence[int]] = None):
        """Set arguments before call function.

        Args:
            args: General arguments.
            va_list: Variable number of arguments.
        """
        for index, value in enumerate(args):
            self.set_arg(index, value)

        if va_list:
            for index, value in enumerate(va_list):
                self.set_arg(self.arch.addr_size + index, value)
            self.set_arg(self.arch.addr_size + len(va_list), 0)

    def get_retval(self) -> int:
        """Get return value."""
        return self.uc.reg_read(self.arch.reg_retval)

    def set_retval(self, value: int):
        """Set return value."""
        self.uc.reg_write(self.arch.reg_retval, value)

    def create_buffer(self, size: int) -> int:
        """Create a buffer with the size."""
        return self.memory_manager.alloc(size)

    def create_string(self, string: str) -> int:
        """Create a buffer that is initialized to the string."""
        address = self.memory_manager.alloc(len(string) + 1)
        self.write_string(address, string)

        return address

    def free(self, address: int):
        """Free memory."""
        self.memory_manager.free(address)

    def read_int(self, address: int, size: int, signed: bool = False) -> int:
        """Read an integer from the address."""
        return int.from_bytes(
            self.uc.mem_read(address, size),
            signed=signed,
            byteorder=self.endian,
        )

    def read_s8(self, address: int) -> int:
        """Read a signed int8 from the address."""
        return self.read_int(address, 1, True)

    def read_s16(self, address: int) -> int:
        """Read a signed int16 from the address."""
        return self.read_int(address, 2, True)

    def read_s32(self, address: int) -> int:
        """Read a signed int32 from the address."""
        return self.read_int(address, 4, True)

    def read_s64(self, address: int) -> int:
        """Read a signed int64 from the address."""
        return self.read_int(address, 8, True)

    def read_u8(self, address: int) -> int:
        """Read an unsigned int8 from the address."""
        return self.read_int(address, 1, False)

    def read_u16(self, address: int) -> int:
        """Read an unsigned int16 from the address."""
        return self.read_int(address, 2, False)

    def read_u32(self, address: int) -> int:
        """Read an unsigned int32 from the address."""
        return self.read_int(address, 4, False)

    def read_u64(self, address: int) -> int:
        """Read an unsigned int64 from the address."""
        return self.read_int(address, 8, False)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the address."""
        return bytes(self.uc.mem_read(address, size))

    def read_string(self, address: int) -> str:
        """Read string from the address."""
        data = bytes()

        block_size = 1024
        end = b"\x00"

        try:
            while True:
                buf = self.read_bytes(address, block_size)
                if buf.find(end) != -1:
                    data += buf[: buf.index(end)]
                    break

                data += buf
                address += block_size
        except UcError:
            for i in range(block_size):
                buf = self.read_bytes(address + i, 1)
                if buf == end:
                    break

                data += buf

        return data.decode("utf-8")

    def read_pointer(self, address: int) -> int:
        """Read a pointer from the address."""
        # print(f"read_pointer address 0x{address:x}")
        return self.read_int(address, self.arch.addr_size)

    def read_array(self, begin: int, end: int, size: Optional[int] = None) -> List[int]:
        """Read an array from the address."""
        if size is None:
            size = self.arch.addr_size

        data = self.read_bytes(begin, end - begin)
        array = []

        for offset in range(0, len(data), size):
            int_bytes = data[offset : offset + size]
            value = int.from_bytes(int_bytes, byteorder=self.endian)
            array.append(value)

        return array

    def write_int(self, address: int, value: int, size: int, signed: bool = False):
        """Write an integer into the address."""
        self.uc.mem_write(
            address,
            value.to_bytes(size, signed=signed, byteorder=self.endian),
        )

    def write_s8(self, address: int, value: int):
        """Write a signed int8 into the address."""
        self.write_int(address, value, 1, True)

    def write_s16(self, address: int, value: int):
        """Write a signed int16 into the address."""
        self.write_int(address, value, 2, True)

    def write_s32(self, address: int, value: int):
        """Write a signed int32 into the address."""
        self.write_int(address, value, 4, True)

    def write_s64(self, address: int, value: int):
        """Write a signed int64 into the address."""
        self.write_int(address, value, 8, True)

    def write_u8(self, address: int, value: int):
        """Write an unsigned int8 into the address."""
        self.write_int(address, value, 1, False)

    def write_u16(self, address: int, value: int):
        """Write an unsigned int16 into the address."""
        self.write_int(address, value, 2, False)

    def write_u32(self, address: int, value: int):
        """Write an unsigned int32 into the address."""
        self.write_int(address, value, 4, False)

    def write_u64(self, address: int, value: int):
        """Write an unsigned int64 into the address."""
        self.write_int(address, value, 8, False)

    def write_bytes(self, address: int, data: bytes):
        """Write bytes into the address."""
        self.uc.mem_write(address, data)

    def write_string(self, address: int, string: str):
        """Write string into the address."""
        self.uc.mem_write(address, string.encode("utf-8") + b"\x00")

    def write_pointer(self, address: int, value: int):
        """Write a pointer into the address."""
        self.write_int(address, value, self.arch.addr_size)

    def write_array(
        self, address: int, array: Sequence[int], size: Optional[int] = None
    ):
        """Write an array into the address."""
        if size is None:
            size = self.arch.addr_size

        data = b""

        for value in array:
            data += value.to_bytes(size, byteorder=self.endian)

        self.write_bytes(address, data)

    def write_zeros(self, address: int, size: int):
        """Write zeros into the address."""
        self.uc.mem_write(address, b"\x00" * size)

    def call_symbol(
        self,
        symbol_name: str,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
    ) -> int:
        """Call function with the symbol name."""
        # self.logger.info(f'Call symbol "{symbol_name}"')

        symbol = self.find_symbol(symbol_name)
        address = symbol.address

        # print(f"call_symbol address 0x{address:x}")
        return self._start_emulate(address, *args, va_list=va_list)

    def call_address(
        self,
        address: int,
        *args: int,
        va_list: Optional[Sequence[int]] = None,
    ) -> int:
        """Call function at the address."""
        return self._start_emulate(address, *args, va_list=va_list)
