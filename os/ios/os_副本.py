import ctypes
import os
import pickle
import plistlib
import sys
from typing import List, Optional

from chomper.const import STACK_ADDRESS, STACK_SIZE
from chomper.exceptions import EmulatorCrashed, SystemOperationFailed
from chomper.loader import MachoLoader, Module
from chomper.os.base import BaseOs, SyscallError
from chomper.utils import log_call, struct2bytes, to_unsigned, aligned

from .fixup import SystemModuleFixup
from .hooks import get_hooks
from .structs import Dirent, Stat64, Statfs64, Timespec
from .syscall import get_syscall_handlers

import lief
from lief.MachO import ARM64_RELOCATION, RelocationFixup

from unicorn import arm64_const

# Environment variables
ENVIRON_VARS = r"""SHELL=/bin/sh
PWD=/var/root
LOGNAME=root
HOME=/var/root
LS_COLORS=rs=0:di=01
CLICOLOR=
SSH_CONNECTION=127.0.0.1 59540 127.0.0.1 22
TERM=xterm
USER=root
SHLVL=1
PS1=\h:\w \u\$
SSH_CLIENT=127.0.0.1 59540 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games
MAIL=/var/mail/root
SSH_TTY=/dev/ttys000
_=/usr/bin/env
SBUS_INSERT_LIBRARIES=/usr/lib/substitute-inserter.dylib
__CF_USER_TEXT_ENCODING=0x0:0:0
CFN_USE_HTTP3=0
CFStringDisableROM=1"""

# Dependent libraries of ObjC
OBJC_DEPENDENCIES = [
    "libsystem_platform.dylib",
    "libsystem_kernel.dylib",
    "libsystem_c.dylib",
    "libsystem_pthread.dylib",
    "libsystem_info.dylib",
    "libsystem_darwin.dylib",
    "libsystem_featureflags.dylib",
    "libsystem_m.dylib",
    "libcorecrypto.dylib",
    "libcommonCrypto.dylib",
    "libcompiler_rt.dylib",
    "libc++abi.dylib",
    "libc++.1.dylib",
    "libmacho.dylib",
    "libdyld.dylib",
    "libsystem_malloc.dylib",
    "libobjc.A.dylib",
    "libdispatch.dylib",
    "libsystem_blocks.dylib",
    "libsystem_trace.dylib",
    "libsystem_sandbox.dylib",
    "libsystem_coreservices.dylib",
    "libsystem_notify.dylib",
    "libnetwork.dylib",
    "libicucore.A.dylib",
    "libcache.dylib",
    "libz.1.dylib",
    "libremovefile.dylib",
    "libxpc.dylib",
    "CoreFoundation",
    "CFNetwork",
    "Foundation",
    "Security",
]

# Dependent libraries of UIKit
UI_KIT_DEPENDENCIES = [
    "QuartzCore",
    "BaseBoard",
    "FrontBoardServices",
    "PrototypeTools",
    "TextInput",
    "PhysicsKit",
    "CoreAutoLayout",
    "IOKit",
    "UIFoundation",
    "UIKitServices",
    "UIKitCore",
    "SystemConfiguration",
    "MediaToolbox",
    "WebBookmarks",
    "PhotoFoundation",
    "UIAccessibility",
    "PhotoLibraryServices",
    "CoreImage",
    "CoreMedia",
    "ColorSync",
    "CoreML",
    "AccessibilityUtilities",
]

# Define symbolic links in the file system
SYMBOLIC_LINKS = {
    "/usr/share/zoneinfo": "/var/db/timezone/zoneinfo",
    "/var/db/timezone/icutz": "/var/db/timezone/tz/2024a.1.0/icutz/",
    "/var/db/timezone/localtime": "/var/db/timezone/zoneinfo/Asia/Shanghai",
    "/var/db/timezone/tz_latest": " /var/db/timezone/tz/2024a.1.0/",
    "/var/db/timezone/zoneinfo": "/var/db/timezone/tz/2024a.1.0/zoneinfo/",
}

# Default bundle values until an executable with Info.plist is loaded
DEFAULT_BUNDLE_UUID = "43E5FB44-22FC-4DC2-9D9E-E2702A988A2E"
DEFAULT_BUNDLE_IDENTIFIER = "com.sledgeh4w.chomper"
DEFAULT_BUNDLE_EXECUTABLE = "Chomper"

DEFAULT_PREFERENCES = {
    "AppleLanguages": [
        "zh-Hans",
        "en",
    ],
    "AppleLocale": "zh-Hans",
}

DEFAULT_DEVICE_INFO = {
    "UserAssignedDeviceName": "iPhone",
    "DeviceName": "iPhone13,1",
    "ProductVersion": "14.2.1",
}


class IosOs(BaseOs):
    """Provide iOS runtime environment."""

    AT_FDCWD = to_unsigned(-2, size=4)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loader = MachoLoader(self.emu)

        self.program_path = (
            f"/private/var/containers/Bundle/Application"
            f"/{DEFAULT_BUNDLE_UUID}"
            f"/{DEFAULT_BUNDLE_IDENTIFIER}"
            f"/{DEFAULT_BUNDLE_EXECUTABLE}"
        )

        self.executable_path = ""

        self.preferences = DEFAULT_PREFERENCES.copy()
        self.device_info = DEFAULT_DEVICE_INFO.copy()

    @property
    def errno(self) -> int:
        """Get the value of `errno`."""
        errno = self.emu.find_symbol("_errno")
        return self.emu.read_u32(errno.address)

    @errno.setter
    def errno(self, value: int):
        """Set the value of `errno`."""
        errno = self.emu.find_symbol("_errno")
        self.emu.write_u32(errno.address, value)

    @staticmethod
    def _construct_stat64(st: os.stat_result) -> bytes:
        """Construct stat64 struct based on `stat_result`."""
        if sys.platform == "win32":
            block_size = 4096

            rdev = 0
            blocks = st.st_size // (block_size // 8) + 1
            blksize = block_size
        else:
            rdev = st.st_rdev
            blocks = st.st_blocks
            blksize = st.st_blksize

        if sys.platform == "darwin":
            flags = st.st_flags
        else:
            flags = 0

        atimespec = Timespec.from_time_ns(st.st_atime_ns)
        mtimespec = Timespec.from_time_ns(st.st_mtime_ns)
        ctimespec = Timespec.from_time_ns(st.st_ctime_ns)

        st = Stat64(
            st_dev=st.st_dev,
            st_mode=st.st_mode,
            st_nlink=st.st_nlink,
            st_ino=st.st_ino,
            st_uid=st.st_uid,
            st_gid=st.st_gid,
            st_rdev=rdev,
            st_atimespec=atimespec,
            st_mtimespec=mtimespec,
            st_ctimespec=ctimespec,
            st_size=st.st_size,
            st_blocks=blocks,
            st_blksize=blksize,
            st_flags=flags,
        )

        return struct2bytes(st)

    @staticmethod
    def _construct_dev_stat64() -> bytes:
        """Construct stat64 struct for device file."""
        atimespec = Timespec.from_time_ns(0)
        mtimespec = Timespec.from_time_ns(0)
        ctimespec = Timespec.from_time_ns(0)

        st = Stat64(
            st_dev=0,
            st_mode=0x2000,
            st_nlink=0,
            st_ino=0,
            st_uid=0,
            st_gid=0,
            st_rdev=0,
            st_atimespec=atimespec,
            st_mtimespec=mtimespec,
            st_ctimespec=ctimespec,
            st_size=0,
            st_blocks=0,
            st_blksize=0,
            st_flags=0,
        )

        return struct2bytes(st)

    @staticmethod
    def _construct_statfs64() -> bytes:
        """Construct statfs64 struct."""
        st = Statfs64(
            f_bsize=4096,
            f_iosize=1048576,
            f_blocks=31218501,
            f_bfree=29460883,
            f_bavail=25672822,
            f_files=1248740040,
            f_ffree=1248421957,
            f_fsid=103095992327,
            f_owner=0,
            f_type=24,
            f_flags=343986176,
            f_fssubtype=0,
            f_fstypename=b"apfs",
            f_mntonname=b"/",
            f_mntfromname=b"/dev/disk0s1s1",
        )
        return struct2bytes(st)

    @staticmethod
    def _construct_dirent(entry: os.DirEntry) -> bytes:
        """Construct dirent struct based on `DirEntry`."""
        st = Dirent(
            d_ino=entry.inode(),
            d_seekoff=0,
            d_reclen=ctypes.sizeof(Dirent),
            d_namlen=len(entry.name),
            d_type=(4 if entry.is_dir() else 0),
            d_name=entry.name.encode("utf-8"),
        )
        return struct2bytes(st)

    @log_call
    def getdirentries(self, fd: int, offset: int) -> Optional[bytes]:
        if fd not in self._dir_fds:
            raise SystemOperationFailed(f"Not a directory: {fd}", SyscallError.ENOTDIR)

        path = self._dir_fds[fd]
        real_path = self._get_real_path(path)

        dir_entries = list(os.scandir(real_path))
        if offset >= len(dir_entries):
            return None

        dir_entry = dir_entries[offset]

        return self._construct_dirent(dir_entry)

    def _setup_hooks(self):
        """Initialize hooks."""
        self.emu.hooks.update(get_hooks())

    def _setup_syscall_handlers(self):
        """Initialize system call handlers."""
        self.emu.syscall_handlers.update(get_syscall_handlers())

    def _setup_kernel_mmio(self):
        """Initialize MMIO used by system libraries."""

        def read_cb(uc, offset, size_, read_ud):
            # arch type
            if offset == 0x23:
                return 0x2
            # vm_page_shift
            elif offset == 0x25:
                return 0xE
            # vm_kernel_page_shift
            elif offset == 0x37:
                return 0xE
            # unknown, appear at _os_trace_init_slow
            elif offset == 0x104:
                return 0x100

            return 0

        def write_cb(uc, offset, size_, value, write_ud):
            pass

        address = 0xFFFFFC000
        size = 0x1000

        self.emu.uc.mmio_map(address, size, read_cb, None, write_cb, None)

    def _init_program_vars(self):
        """Initialize program variables, works like `__program_vars_init`."""
        argc = self.emu.create_buffer(8)
        self.emu.write_int(argc, 0, 8)

        nx_argc_pointer = self.emu.find_symbol("_NXArgc_pointer")
        self.emu.write_pointer(nx_argc_pointer.address, argc)

        nx_argv_pointer = self.emu.find_symbol("_NXArgv_pointer")
        self.emu.write_pointer(nx_argv_pointer.address, self.emu.create_string(""))

        environ = self.emu.create_buffer(8)
        self.emu.write_pointer(environ, self._construct_environ(ENVIRON_VARS))

        environ_pointer = self.emu.find_symbol("_environ_pointer")
        self.emu.write_pointer(environ_pointer.address, environ)

        progname_pointer = self.emu.find_symbol("___progname_pointer")
        self.emu.write_pointer(progname_pointer.address, self.emu.create_string(""))

        self.emu.call_address(0x1890FA640) #__atexit_init

    def _init_dyld_vars(self):
        """Initialize global variables in `libdyld.dylib`."""
        g_use_dyld3 = self.emu.find_symbol("_gUseDyld3")
        self.emu.write_u8(g_use_dyld3.address, 1)

        dyld_all_images = self.emu.find_symbol("__ZN5dyld310gAllImagesE")

        # dyld3::closure::ContainerTypedBytes::findAttributePayload
        attribute_payload_ptr = self.emu.create_buffer(8)

        self.emu.write_u32(attribute_payload_ptr, 2**10)
        self.emu.write_u8(attribute_payload_ptr + 4, 0x20)

        self.emu.write_pointer(dyld_all_images.address, attribute_payload_ptr)

        # dyld3::AllImages::platform
        platform_ptr = self.emu.create_buffer(0x144)
        self.emu.write_u32(platform_ptr + 0x140, 2)

        self.emu.write_pointer(dyld_all_images.address + 0x50, platform_ptr)

        # environ
        environ_pointer = self.emu.find_symbol("_environ_pointer")
        environ_value = self.emu.read_pointer(environ_pointer.address)

        environ_buf = self.emu.create_buffer(8)
        self.emu.write_pointer(environ_buf, environ_value)

        environ = self.emu.find_symbol("_environ")
        self.emu.write_pointer(environ.address, environ_buf)

    def _init_lib_system_kernel(self):
        """Initialize `libsystem_kernel.dylib`."""
        # print(f"call _mach_init_doit {self.emu.uc.mem_read(0x1AB4758C4,4)} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")
        self.emu.call_symbol("_mach_init_doit")

    def _init_lib_system_pthread(self):
        """Initialize `libsystem_pthread.dylib`."""
        main_thread = self.emu.create_buffer(256)

        self.emu.write_pointer(main_thread + 0xB0, STACK_ADDRESS)
        self.emu.write_pointer(main_thread + 0xE0, STACK_ADDRESS + STACK_SIZE)

        main_thread_ptr = self.emu.find_symbol("__main_thread_ptr")
        self.emu.write_pointer(main_thread_ptr.address, main_thread)

    def _init_lib_xpc(self):
        """Initialize `libxpc.dylib`."""
        try:
            self.emu.call_symbol("__libxpc_initializer")
        except EmulatorCrashed:
            pass

    def _init_objc_vars(self):
        """Initialize global variables in `libobjc.A.dylib
        while calling `__objc_init`."""
        prototypes = self.emu.find_symbol("__ZL10prototypes")
        self.emu.write_u64(prototypes.address, 0)

        gdb_objc_realized_classes = self.emu.find_symbol("_gdb_objc_realized_classes")
        protocolsv_ret = self.emu.call_symbol("__ZL9protocolsv")

        self.emu.write_pointer(gdb_objc_realized_classes.address, protocolsv_ret)

        opt = self.emu.find_symbol("__ZL3opt")
        self.emu.write_pointer(opt.address, 0)

        # Disable pre-optimization
        disable_preopt = self.emu.find_symbol("_DisablePreopt")
        self.emu.write_u8(disable_preopt.address, 1)

        self.emu.call_symbol("__objc_init")

    def init_objc(self, module: Module):
        """Initialize Objective-C for the module.

        Calling `map_images` and `load_images` of `libobjc.A.dylib`.
        """
        if not module.binary or module.image_base is None:
            return

        if not self.emu.find_module("libobjc.A.dylib"):
            return

        text_segment = module.binary.get_segment("__TEXT")

        mach_header_ptr = module.base - module.image_base + text_segment.virtual_address
        mach_header_ptrs = self.emu.create_buffer(self.emu.arch.addr_size)

        mh_execute_header_pointer = self.emu.find_symbol("__mh_execute_header_pointer")

        self.emu.write_pointer(mach_header_ptrs, mach_header_ptr)
        self.emu.write_pointer(mh_execute_header_pointer.address, mach_header_ptr)

        try:
            self.emu.call_symbol("_map_images", 1, 0, mach_header_ptrs)
            self.emu.call_symbol("_load_images", 0, mach_header_ptr)
        except EmulatorCrashed:
            self.emu.logger.warning("Initialize Objective-C failed.")

            # Release locks
            runtime_lock = self.emu.find_symbol("_runtimeLock")
            self.emu.write_u64(runtime_lock.address, 0)

            lcl_rwlock = self.emu.find_symbol("_lcl_rwlock")
            self.emu.write_u64(lcl_rwlock.address, 0)

    def search_module_binary(self, module_name: str) -> str:
        """Search system module binary in rootfs directory.

        raises:
            FileNotFoundError: If module not found.
        """
        lib_dirs = [
            "usr/lib/system",
            "usr/lib",
            "System/Library/Frameworks",
            "System/Library/PrivateFrameworks",
        ]

        for lib_dir in lib_dirs:
            path = os.path.join(self.rootfs_path or ".", lib_dir)

            lib_path = os.path.join(path, module_name)
            if os.path.exists(lib_path):
                return lib_path

            framework_path = os.path.join(path, f"{module_name}.framework")
            if os.path.exists(framework_path):
                return os.path.join(framework_path, module_name)

        raise FileNotFoundError("Module '%s' not found" % module_name)

    def merge_memory_ranges(self, vm_orig_info):
        """
        合并内存地址范围

        规则：
        - 重叠的区域（如A的结束地址 > B的开始地址）会被合并
        - 连续的区域（如A的结束地址 == B的开始地址）会被合并
        - 不连续的区域（如A的结束地址 < B的开始地址）会被保留为独立条目
        """
        if not vm_orig_info:
            return []

        # 转换为(开始地址, 结束地址)格式，便于比较
        ranges = []
        for vm_addr, vm_size in vm_orig_info:
            start = vm_addr
            end = vm_addr + vm_size  # 计算结束地址（不包含在范围内）
            ranges.append((start, end))

        # 按开始地址排序，确保按内存顺序处理
        sorted_ranges = sorted(ranges, key=lambda x: x[0])

        # 初始化合并列表，放入第一个范围
        merged = [sorted_ranges[0]]

        # 遍历剩余范围进行合并判断
        for current_start, current_end in sorted_ranges[1:]:
            # 获取最后一个已合并的范围
            last_start, last_end = merged[-1]

            # 情况1：当前范围与最后一个范围重叠或连续（需要合并）
            if current_start <= last_end:
                # 合并后的范围取最小开始和最大结束
                new_start = last_start
                new_end = max(last_end, current_end)
                merged[-1] = (new_start, new_end)

            # 情况2：当前范围与最后一个范围不连续（无需合并，直接添加）
            else:
                merged.append((current_start, current_end))

        # 转换回(开始地址, 大小)格式
        result = [(start, end - start) for start, end in merged]
        return result

    def map_all_modules(self, module_names: List[str]):
        vm_maps_info = []
        vm_write_info = []
        for module_name in module_names:
            print(f"module_name {module_name}")
            # print(f"module_name {module_name}")
            if self.emu.find_module(module_name):
                continue
            module_file = self.search_module_binary(module_name)
            binary: lief.MachO.Binary = lief.parse(module_file)  # type: ignore

            for segment in binary.segments:
                segment_map_addr = aligned(segment.virtual_address, 1024) - (1024 if segment.virtual_address % 1024 else 0)
                segment_map_size = aligned(segment.virtual_address - segment_map_addr + segment.virtual_size, 1024)
                vm_maps_info.append((segment_map_addr,segment_map_size))
                # print(f"module_name {module_name} segment {segment} segment.name {segment.name} vm_write_info segment.virtual_address 0x{segment.virtual_address:x} segment.content {segment.content} segment.size {segment.size} len(segment.content) {len(segment.content)}")
                # print(f"segment.virtual_address 0x{segment.virtual_address:x} segment.content: {segment.content} len: 0x{len(segment.content):x} segment.content[:4] {' '.join(f'0x{byte:02x}' for byte in segment.content[:4])}")
                vm_write_info.append((segment.virtual_address,bytearray(segment.content)))
                for section in segment.sections:
                    if section.size > 0:
                        section_map_addr = aligned(section.virtual_address, 1024) - (1024 if section.virtual_address % 1024 else 0)
                        section_map_size = aligned(section.virtual_address - section_map_addr + section.size, 1024)
                        vm_maps_info.append((section_map_addr,section_map_size))
                        # print(f"module_name {module_name} section {section} section.name {section.name} vm_write_info section.virtual_address 0x{section.virtual_address:x} section.content {section.content} section.size {section.size} len(section.content) {len(section.content)} section.content[:4] {' '.join(f'0x{byte:02x}' for byte in section.content[0x2384:0x2384+4])}")
                        vm_write_info.append((section.virtual_address,bytearray(section.content)))

        vm_maps_info = self.merge_memory_ranges(vm_maps_info)
        for addr,size in vm_maps_info:
            # print(f"map addr: 0x{addr:x} size: 0x{size:x}")
            self.emu.uc.mem_map(addr, size)

        for virtual_address,content in vm_write_info:
            if len(content) > 0:
                print(f"write virtual_address 0x{virtual_address:x} len 0x{len(content):x}")
                self.emu.uc.mem_write(
                    virtual_address,
                    bytes(content),
                )
                # print(f"map_all_modules {' '.join(f'0x{byte:02x}' for byte in self.emu.uc.mem_read(0x1AB4758C4,4))} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")

        # for module_name in module_names:
        #     # print(f"module_name {module_name}")
        #     if self.emu.find_module(module_name):
        #         continue
        #     module_file = self.search_module_binary(module_name)
        #     binary: lief.MachO.Binary = lief.parse(module_file)  # type: ignore

        #     # print(f"binary.header: {dir(binary.header)}")
        #     # print(f"binary.header.__sizeof__: {binary.header.__sizeof__}")
        #     # for command in binary.commands:
        #     #     print(f"{dir(command)}")

        #     is_first_segment = True
        #     for segment in binary.segments:
        #         if is_first_segment:
        #             is_first_segment = False

        #             print(f"binary.header.cpu_type:{binary.header.cpu_type} type: {type(binary.header.cpu_type)} value: {binary.header.cpu_type.value}")
        #             print(f"segment.virtual_address: 0x{segment.virtual_address:x}")
        #             self.emu.uc.mem_write(
        #                 segment.virtual_address + 4,
        #                 bytes(binary.header.cpu_type.value),
        #             )

        #             print(f"binary.header.cpu_subtype:{binary.header.cpu_subtype} type: {type(binary.header.cpu_subtype)} len: {dir(binary.header.cpu_subtype.to_bytes())}")
        #             print(f"segment.virtual_address 0x{segment.virtual_address:x}")

                    # binary.header.cpu_subtype.to_bytes()

    # 定义错误钩子：当发生未映射内存读操作时触发
    def hook_mem_read_unmapped(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")

    def hook_mem_read_unmapped_1(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x22 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X22')):x}")

    def hook_mem_read_unmapped_2(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        _x1 = self.emu.read_u64(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')))
        print(f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x}:0x{_x1:x} x22 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X22')):x}")

    def hook_mem_read_unmapped_3(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        _x19 = self.emu.read_u64(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')))
        print(f"x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x}:0x{_x19:x}")

    def hook_mem_read_unmapped_4(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        _x0 = self.emu.read_u64(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')))
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x}:0x{_x0:x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x}")

    def hook_mem_read_unmapped_5(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        _x12 = self.emu.read_u64(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X12')))
        print(f"x12 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X12')):x}:0x{_x12:x}")

    def hook_mem_read_unmapped_6(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x25 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X25')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x}")

    def hook_mem_read_unmapped_7(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x22 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X22')):x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x}")

    def hook_mem_read_unmapped_193E2E7DC(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x}")
        print(f"[x1] {self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')),8)}")

    def resolve_modules(self, module_names: List[str]):
        """Load system modules if don't loaded."""
        fixup = SystemModuleFixup(self.emu)

        # resolve modules memery
        # self.map_all_modules(module_names)
        # print(f"resolve_modules 1 {self.emu.uc.mem_read(0x1AB4758C4,4)} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")

        # print(f"resolve_modules resolve_modules")
        # self.emu.add_hook(0x193E2E7A8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E351B8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E7DC, self.hook_mem_read_unmapped_193E2E7DC)
        # self.emu.add_hook(0x193E2E824, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6AC1018, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6AC1054, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ABCE10, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1AB49A288, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ABCD2C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ABCE90, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ABCEA4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1890FAE28, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ACCC08, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1C6ACCC80, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193F19EBC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193F19EE8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193EDAF9C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1890FAE24, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1890603A4, self.hook_mem_read_unmapped)


        # self.emu.add_hook(0x1800CA8A0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800CA8B4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800CA8F8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800CA880, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E3F5E8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800CA518, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800D7544, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800CA5A8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800D7560, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800C7AA0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800C7B08, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800C7AC0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1800D4BE8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E352F0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E78C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E3524C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E35268, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E35294, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E83C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E84C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2D534, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E7D8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E7F4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E7DC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E35194, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E22028, self.hook_mem_read_unmapped_2)
        # self.emu.add_hook(0x193E21FEC, self.hook_mem_read_unmapped_1)
        # self.emu.add_hook(0x193E265A8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E265A4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E26570, self.hook_mem_read_unmapped_3)
        # self.emu.add_hook(0x193E26508, self.hook_mem_read_unmapped_4)
        # self.emu.add_hook(0x193E20704, self.hook_mem_read_unmapped_5)
        # self.emu.add_hook(0x193E20714, self.hook_mem_read_unmapped_4)
        # self.emu.add_hook(0x193E21B98, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E21B80, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x1803EE988, self.hook_mem_read_unmapped_6)
        # self.emu.add_hook(0x193E37C64, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37C78, self.hook_mem_read_unmapped_7)
        # self.emu.add_hook(0x193E37C40, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37C60, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37CC4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37CCC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37DC4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37DCC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37E58, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37E60, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37E8C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37F40, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37F88, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37F10, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37FA4, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37FB0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37FC0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E38020, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37E80, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E37DBC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E38034, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E38060, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E380A0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E380F8, self.hook_mem_read_unmapped)

        # self.emu.add_hook(0x193E38168, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E38120, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E38130, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E296D0, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E296EC, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E29708, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2974C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BE34, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BD74, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BDD8, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BE1C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BD88, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E1BD84, self.hook_mem_read_unmapped)








        for module_name in module_names:
            if self.emu.find_module(module_name):
                continue

            module_file = self.search_module_binary(module_name)
            module = self.emu.load_module(
                module_file=module_file,
                exec_objc_init=False,
            )
            # print(f"resolve_modules 2 {self.emu.uc.mem_read(0x1AB4758C4,4)} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")
            # Fixup must be executed before initializing Objective-C.
            fixup.install(module)

            self._after_module_loaded(module_name)

            self.init_objc(module)

            module.binary = None

    def _after_module_loaded(self, module_name: str):
        print(f"_after_module_loaded module_name: {module_name}")
        """Perform initialization after module loaded."""
        if module_name == "libsystem_kernel.dylib":
            self._init_lib_system_kernel()
        elif module_name == "libsystem_c.dylib":
            self._init_program_vars()
        elif module_name == "libdyld.dylib":
            self._init_dyld_vars()
        elif module_name == "libsystem_pthread.dylib":
            self._init_lib_system_pthread()
        elif module_name == "libobjc.A.dylib":
            self._init_objc_vars()

    def _enable_objc(self):
        """Enable Objective-C support."""
        self.resolve_modules(OBJC_DEPENDENCIES)

        symbol_dataSegmentsRanges = self.emu.find_symbol("_dataSegmentsRanges")
        print(f"symbol_dataSegmentsRanges {symbol_dataSegmentsRanges}")
        self.emu.write_u64(symbol_dataSegmentsRanges.address, 0x180000000)
        self.emu.write_u64(symbol_dataSegmentsRanges.address + 8, 0x1E7BA4000)

        self._init_lib_xpc()

        # Call initialize function of `CoreFoundation`
        self.emu.call_symbol("___CFInitialize")

        is_cf_prefs_d = self.emu.find_symbol("_isCFPrefsD")
        self.emu.write_u8(is_cf_prefs_d.address, 1)

        # Call initialize function of `Foundation`
        self.emu.call_symbol("__NSInitializePlatform")

        self.fix_method_signature_rom_table()

        amkrtemp_sentinel = self.emu.find_symbol("__amkrtemp.sentinel")
        self.emu.write_pointer(amkrtemp_sentinel.address, self.emu.create_string(""))

    def _enable_ui_kit(self):
        """Enable UIKit support.

        Mainly used to load `UIDevice` class, which is used to get device info.
        """
        self.resolve_modules(UI_KIT_DEPENDENCIES)

    def _setup_symbolic_links(self):
        """Setup symbolic links."""
        for src, dst in SYMBOLIC_LINKS.items():
            self.set_symbolic_link(src, dst)

    def _setup_bundle_dir(self):
        """Setup bundle directory."""
        bundle_path = os.path.dirname(self.program_path)
        container_path = os.path.dirname(bundle_path)

        self.set_working_dir(bundle_path)

        local_container_path = os.path.join(
            self.rootfs_path,
            "private",
            "var",
            "containers",
            "Bundle",
            "Application",
            DEFAULT_BUNDLE_UUID,
        )
        local_bundle_path = os.path.join(
            local_container_path, DEFAULT_BUNDLE_IDENTIFIER
        )

        self.forward_path(container_path, local_container_path)
        self.forward_path(bundle_path, local_bundle_path)

    def set_main_executable(self, executable_path: str):
        """Set main executable path."""
        self.executable_path = executable_path

        bundle_path = os.path.dirname(self.program_path)
        container_path = os.path.dirname(bundle_path)

        executable_dir = os.path.dirname(self.executable_path)
        info_path = os.path.join(executable_dir, "Info.plist")

        if os.path.exists(info_path):
            with open(info_path, "rb") as f:
                info_data = plistlib.load(f)

            bundle_identifier = info_data["CFBundleIdentifier"]
            bundle_executable = info_data["CFBundleExecutable"]

            bundle_path = f"{container_path}/{bundle_identifier}"
            self.program_path = f"{bundle_path}/{bundle_executable}"

            self._setup_bundle_dir()

            cf_progname = self.emu.find_symbol("___CFprogname")
            cf_process_path = self.emu.find_symbol("___CFProcessPath")

            cf_progname_str = self.emu.create_string(self.program_path.split("/")[-1])
            cf_process_path_str = self.emu.create_string(self.program_path)

            self.emu.write_pointer(cf_progname.address, cf_progname_str)
            self.emu.write_pointer(cf_process_path.address, cf_process_path_str)

        # Set path forwarding to executable and Info.plist
        self.forward_path(
            src_path=self.program_path,
            dst_path=self.executable_path,
        )
        self.forward_path(
            src_path=f"{bundle_path}/Info.plist",
            dst_path=info_path,
        )

    def fix_method_signature_rom_table(self):
        """Fix MethodSignatureROMTable by using pre dumped data file."""
        if sys.version_info >= (3, 9):
            import importlib.resources

            data_path = importlib.resources.files(__package__.split(".")[0]) / "res"
        else:
            import pkg_resources

            data_path = pkg_resources.resource_filename(
                __package__.split(".")[0], "res"
            )

        with open(os.path.join(data_path, "method_signature_rom_table.pkl"), "rb") as f:
            table_data = pickle.load(f)

        table = self.emu.find_symbol("_MethodSignatureROMTable")

        for index, item in enumerate(table_data):
            offset = table.address + index * 24
            str_ptr = self.emu.create_string(item[1])

            self.emu.write_pointer(offset + 8, str_ptr)
            self.emu.write_u64(offset + 16, item[2])

    def _create_fp(self, fd: int, mode: str, unbuffered: bool = False) -> int:
        """Wrap file descriptor to file object by calling `fdopen`."""
        mode_p = self.emu.create_string(mode)

        try:
            fp = self.emu.call_symbol("_fdopen", fd, mode_p)
            flags = self.emu.read_u32(fp + 16)

            if unbuffered:
                flags |= 0x2

            self.emu.write_u32(fp + 16, flags)
            return fp
        finally:
            self.emu.free(mode_p)

    def _setup_standard_io(self):
        """Setup standard IO: `stdin`, `stdout`, `stderr`."""
        stdin_p = self.emu.find_symbol("___stdinp")
        stdout_p = self.emu.find_symbol("___stdoutp")
        stderr_p = self.emu.find_symbol("___stderrp")

        if isinstance(self.stdin, int):
            stdin_fp = self._create_fp(self.stdin, "r")
            self.emu.write_pointer(stdin_p.address, stdin_fp)

        stdout_fp = self._create_fp(self.stdout, "w", unbuffered=True)
        self.emu.write_pointer(stdout_p.address, stdout_fp)

        stderr_fp = self._create_fp(self.stderr, "w", unbuffered=True)
        self.emu.write_pointer(stderr_p.address, stderr_fp)

    def initialize(self):
        """Initialize environment."""
        self._setup_hooks()
        self._setup_syscall_handlers()
        self._setup_devices()

        self._setup_kernel_mmio()

        self._setup_symbolic_links()
        self._setup_bundle_dir()

        ALL_MODULES = OBJC_DEPENDENCIES + UI_KIT_DEPENDENCIES
        self.map_all_modules(ALL_MODULES)

        if self.emu.enable_objc:
            self._enable_objc()

        if self.emu.enable_ui_kit:
            self._enable_ui_kit()

        self._setup_standard_io()
