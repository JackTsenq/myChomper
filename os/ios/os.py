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

from unicorn import arm64_const, UcError

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
    "libcompression.dylib", #taobao
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
]

ONLY_MAP = [
    "PN548_API.dylib",
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
    "IOSurface",
    "CoreUI",
    "Combine",
    "iWorkXPC_TSUtility",
    "WebCore",
    "iWorkImport_TSUtility",
    "libimg4.dylib",
    "libEDR",
    "CoreText",
    "CoreServices",
    "MobileAsset",
    "WebKitLegacy",
    "Pasteboard",
    "ShareSheet",
    "UserNotifications",
    "libWirelessAudioIPC.dylib",
    "libCRFSuite.dylib",
    "ContextKitExtraction",
    "CoreHaptics",
    "libsystem_containermanager.dylib",
    "libFaultOrdering.dylib",
    "CoreVideo",
    "CMCapture",
    "libAppleArchive.dylib", #taobao
    "CoreParsec", #taobao
    "AssetsLibraryServices", #taobao
    "libGSFont.dylib",
    "AppleCV3D",
    "RealityKit",
    "libGSFontCache.dylib",
    "AppleFSCompression",
    "PDFKit",
    "CoreGraphics",
    "libMobileGestalt.dylib",
    "UIKit",
    "DataMigration",
    "CoreDuetContext",
    "MultipeerConnectivity",
    "SceneKit",
    "AppleCV3DMOVKit",
    "DesktopServicesPriv",
    "DeviceToDeviceManager",
    "SoundAnalysis",
    "DiagnosticsKit",
    "OpenGLES",
    "libFontParser.dylib",
    "CoreSDB",
    "ActionKit",
    "H6ISP.mediacapture",
    "ABMHelper",
    "libunwind.dylib",
    "ImageIO",
    "FontServices",
    "libMemoryResourceException.dylib",
    "AudioToolbox",
    "Montreal",
    "CoreServicesInternal",
]

# 导出 ALL_MODULES 供其他模块使用
ALL_MODULES = OBJC_DEPENDENCIES + UI_KIT_DEPENDENCIES + ONLY_MAP

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

    AF_UNIX = 1
    AF_INET = 2

    SOCK_STREAM = 1

    IPPROTO_IP = 0
    IPPROTO_ICMP = 1

    MACH_PORT_NULL = 0
    MACH_PORT_HOST_SELF = 1
    MACH_PORT_TASK_SELF = 2
    MACH_PORT_TIMER = 3
    MACH_PORT_NOTIFICATION_CENTER = 4


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
        
        # Initialize thread management
        self._threads = {}

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
        
        # MMIO区域数据存储，基于真机dump数据初始化
        self.mmio_data = {}
        
        # 根据真机dump数据初始化MMIO区域 (16进制int64_t数据)
        # 地址 0xFFFFFC000: 656761706d6d6f63
        self.mmio_data[0x0] = 0x656761706d6d6f63
        
        # 地址 0xFFFFFC008: 7469622d343620
        self.mmio_data[0x8] = 0x7469622d343620
        
        # 地址 0xFFFFFC010: 10237a0
        self.mmio_data[0x10] = 0x10237a0
        
        # 地址 0xFFFFFC018: 3000000000000
        self.mmio_data[0x18] = 0x3000000000000
        
        # 地址 0xFFFFFC020: 400e0e010237a0 (包含我们需要的0x400e0e01)
        self.mmio_data[0x20] = 0x400e0e010237a0
        
        # 地址 0xFFFFFC028: 0
        self.mmio_data[0x28] = 0x0
        
        # 地址 0xFFFFFC030: e02020200000000
        self.mmio_data[0x30] = 0xe02020200000000
        
        # 地址 0xFFFFFC038: 7da64000
        self.mmio_data[0x38] = 0x7da64000

        def read_cb(uc, offset, size_, read_ud):
            # print(f"read_cb offset {offset} size_ {size_}")
            
            # 计算对齐的偏移量（8字节对齐）
            aligned_offset = offset & ~0x7
            
            # 从存储的数据中读取
            if aligned_offset in self.mmio_data:
                value = self.mmio_data[aligned_offset]
                
                # 计算字节偏移
                byte_offset = offset - aligned_offset
                
                # 提取相应位置的数据
                if size_ == 1:
                    extracted = (value >> (byte_offset * 8)) & 0xFF
                elif size_ == 2:
                    extracted = (value >> (byte_offset * 8)) & 0xFFFF
                elif size_ == 4:
                    extracted = (value >> (byte_offset * 8)) & 0xFFFFFFFF
                elif size_ == 8:
                    extracted = value
                else:
                    extracted = 0
                
                # print(f"read_cb: offset={offset}, aligned_offset={aligned_offset}, byte_offset={byte_offset}, value=0x{value:x}, extracted=0x{extracted:x}")
                return extracted
            else:
                # 保持原有的硬编码逻辑作为后备
                if offset == 0x23:
                    return 0x2
                elif offset == 0x25:
                    return 0xE
                elif offset == 0x37:
                    return 0xE
                elif offset == 0x104:
                    return 0x100
            
            return 0

        def write_cb(uc, offset, size_, value, write_ud):
            # 支持MMIO写入操作
            if size_ == 1:
                mask = 0xFF
            elif size_ == 2:
                mask = 0xFFFF
            elif size_ == 4:
                mask = 0xFFFFFFFF
            elif size_ == 8:
                mask = 0xFFFFFFFFFFFFFFFF
            else:
                return
            
            # 确保偏移量对齐
            aligned_offset = offset & ~(size_ - 1)
            
            # 读取当前值
            current_value = self.mmio_data.get(aligned_offset, 0)
            
            # 计算写入位置
            byte_offset = offset - aligned_offset
            shift = byte_offset * 8
            
            # 清除目标位置的值
            clear_mask = ~(mask << shift)
            current_value &= clear_mask
            
            # 写入新值
            new_value = (value & mask) << shift
            current_value |= new_value
            
            # 保存更新后的值
            self.mmio_data[aligned_offset] = current_value
            
            # print(f"MMIO Write: offset=0x{offset:x}, size={size_}, value=0x{value:x}, result=0x{current_value:x}")

        address = 0xFFFFFC000
        size = 0x1000

        self.emu.uc.mmio_map(address, size, read_cb, None, write_cb, None)
    
    def debug_mmio_region(self):
        """调试MMIO区域，打印当前状态"""
        print("=== MMIO Region Debug Info ===")
        base_addr = 0xFFFFFC000
        
        for offset in sorted(self.mmio_data.keys()):
            addr = base_addr + offset
            value = self.mmio_data[offset]
            print(f"Address 0x{addr:x}: 0x{value:x}")
        
        # 特别检查0xFFFFFC023处的值
        test_addr = 0xFFFFFC023
        test_offset = test_addr - base_addr
        if test_offset in self.mmio_data:
            aligned_offset = test_offset & ~0x7  # 8字节对齐
            byte_offset = test_offset - aligned_offset
            value = self.mmio_data[aligned_offset]
            extracted = (value >> (byte_offset * 8)) & 0xFFFFFFFF
            print(f"Address 0x{test_addr:x} (offset 0x{test_offset:x}): 0x{extracted:x}")
        print("===============================")

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
            "System/Library/MediaCapture",
        ]

        for lib_dir in lib_dirs:
            path = os.path.join(self.rootfs_path or ".", lib_dir)

            # 直接搜索 dylib 文件
            lib_path = os.path.join(path, module_name)
            if os.path.exists(lib_path):
                return lib_path

            # 搜索 framework 中的主二进制文件
            framework_path = os.path.join(path, f"{module_name}.framework")
            if os.path.exists(framework_path):
                return os.path.join(framework_path, module_name)

            # 搜索 framework 内部的 dylib 文件
            # 例如：FontServices.framework/libGSFont.dylib
            for framework_name in os.listdir(path) if os.path.exists(path) else []:
                if framework_name.endswith('.framework'):
                    framework_dir = os.path.join(path, framework_name)
                    if os.path.isdir(framework_dir):
                        # 在 framework 内部搜索 dylib 文件
                        dylib_path = os.path.join(framework_dir, module_name)
                        if os.path.exists(dylib_path):
                            return dylib_path

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
        binaries = []
        
        # 初始化 dyld 信息字典，用于 _dyld_get_image_header 函数
        if not hasattr(self, '_dyld_image_info'):
            self._dyld_image_info = {}
        
        for module_name in module_names:
            # print(f"module_name {module_name}")
            # print(f"module_name {module_name}")
            # if self.emu.find_module(module_name):
            #     continue
            module_file = self.search_module_binary(module_name)
            binary: lief.MachO.Binary = lief.parse(module_file)  # type: ignore
            binaries.append(binary)

            # 获取模块的第一个段的首地址作为基地址
            first_segment = None
            for segment in binary.segments:
                if segment.virtual_address > 0:
                    first_segment = segment
                    break
            
            if first_segment:
                # 计算段映射地址
                segment_map_addr = aligned(first_segment.virtual_address, 1024) - (1024 if first_segment.virtual_address % 1024 else 0)
                
                # 存储 dyld 信息到字典中
                image_index = len(self._dyld_image_info)
                self._dyld_image_info[image_index] = {
                    'dli_fname': module_file,  # 模块文件路径
                    'dli_fbase': segment_map_addr,  # 模块基地址
                    'dli_sname': '__dso_handle',  # 固定符号名
                    'dli_saddr': segment_map_addr,  # 符号地址（使用基地址）
                    'module_name': module_name,  # 模块名称（用于调试）
                }

            for segment in binary.segments:
                segment_map_addr = aligned(segment.virtual_address, 1024) - (1024 if segment.virtual_address % 1024 else 0)
                segment_map_size = aligned(segment.virtual_address - segment_map_addr + segment.virtual_size, 1024)
                vm_maps_info.append((segment_map_addr,segment_map_size))
                # print(f"module_name {module_name} segment_map_addr 0x{segment_map_addr:x} segment_map_size 0x{segment_map_size:x}");
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
                # print(f"write virtual_address 0x{virtual_address:x} len 0x{len(content):x}")
                self.emu.uc.mem_write(
                    virtual_address,
                    bytes(content),
                )
                # print(f"map_all_modules {' '.join(f'0x{byte:02x}' for byte in self.emu.uc.mem_read(0x1AB4758C4,4))} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")

        for binary in binaries:
            for segment in binary.segments:
                if segment.name in ["__DATA", "__DATA_DIRTY"]:
                    for section in segment.sections:
                        if section.name == "__bss":
                            if section:
                                print(f"memset_bss_section: found __bss segment - virtual_address: 0x{section.virtual_address:x}, size: {section.size}")
                                self.emu.write_zeros(section.virtual_address, section.size)

        # if module.name == "UIKitCore":
        #     print(f"UIKitCore 0x1D616ED08:{self.emu.uc.mem_read(0x1D616ED08,8)}")

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
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
        f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
        f"x2 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
        f"x3 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X3')):x} "
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
        f"x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} "
        f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")  

    def hook_mem_read_unmapped_1AB4994D4(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        self.emu.log_backtrace()

        # try:
        #     print(f"0x80228e0: 0x{self.emu.uc.mem_read(0x80228e0, 4)}")
        # except UcError:
        #     print("0x80228e0: 内存未映射")
            
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

    def hook_mem_read_unmapped_180470014(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x2 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")

    def hook_mem_read_unmapped_dump_1d61157c8(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x} x16 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X16')):x} x17 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X17')):x} x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        print(f"0x1D61157C8: 0x{self.emu.uc.mem_read(0x1D61157C8, 8)}")
        print(f"0x1D61157D0: 0x{self.emu.uc.mem_read(0x1D61157D0, 8)}")
        print(f"0x1D61157D8: 0x{self.emu.uc.mem_read(0x1D61157D8, 8)}")
        print(f"0x1D61157E0: 0x{self.emu.uc.mem_read(0x1D61157E0, 8)}")
        try:
            print(f"0x80228e0: 0x{self.emu.uc.mem_read(0x80228e0, 4)}")
        except UcError:
            print("0x80228e0: 内存未映射")

    def hook_mem_read_unmapped_dump_193E23FDC(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x}:0x{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')), 4)}")
    
    def hook_mem_read_unmapped_dump_193E33DB0(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x}")

    def hook_mem_read_unmapped_dump_193E33D64(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x}")
    
    def hook_mem_read_unmapped_dump_193E33D54(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} 0x1D6103F48:0x{self.emu.uc.mem_read(0x1D6103F48, 8)} 0x1D6103F50:0x{self.emu.uc.mem_read(0x1D6103F50, 4)} 0x1D6103F54:0x{self.emu.uc.mem_read(0x1D6103F54, 4)}")
    
    def hook_mem_read_unmapped_dump_193E33D74(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x12 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X12')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x}")

    def hook_mem_read_unmapped_dump_193E33D90(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x}")
        print(f"0x1d6119850:0x{self.emu.uc.mem_read(0x1d6119850, 8)}")

    def hook_mem_read_unmapped_dump_193e1c47c(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x} x10 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X10')):x} x11 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X11')):x} x16 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X16')):x} x17 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X17')):x} x19 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X19')):x} x20 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X20')):x} x23 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X23')):x} x24 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X24')):x} x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        print(f"x9: 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x}:{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')), 4)}")
        print(f"x9 + 4: 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')+4):x}:{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')) + 4, 4)}")
        print(f"x9 + 8: 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')+8):x}:{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')) + 8, 4)}")
        print(f"x9 + 12: 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')+12):x}:{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')) + 12, 4)}")
    
    def hook_mem_read_unmapped_dump_193E1C480(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} x9 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')):x}:{self.emu.uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X9')), 4)}")
    
    def hook_mem_read_unmapped_callStack(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x3 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X3')):x} "
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
            f"x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} "
            f"x29 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X29')):x} "
            f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")  

    def hook_mem_read_unmapped_1C6ABB084(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x}");
        # self.debug_mmio_region()

    def hook_mem_read_unmapped_1C6ABB080(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x8 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')):x}:0x{int.from_bytes(uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X8')),8), byteorder=self.emu.endian):x}");

    def hook_mem_read_unmapped_1817209EC(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
        )
        self.dumpMemeryWithWidth(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')), 5)
        self.dumpMemeryWithWidth(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')), 5)
        self.emu.log_backtrace()

    def dumpMemeryWithWidth(self, addr: int, width: int):
        """Dump memory with specified width, similar to Objective-C version.
        
        Args:
            addr: Memory address to start dumping from
            width: Number of int64_t values to dump
        """
        print("-------------------------------------------")
        for i in range(width):
            try:
                # Read 8 bytes (int64_t) from memory
                mem_data = self.emu.uc.mem_read(addr + i * 8, 8)
                # Convert bytes to int64_t value
                value = int.from_bytes(mem_data, byteorder=self.emu.endian, signed=True)
                print(f"memery dump >{addr + i * 8:x}:{value:x}<")
            except Exception as e:
                print(f"memery dump >{addr + i * 8:x}:<error reading memory: {e}>")

    def hook_mem_read_unmapped_1817209D4(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        self.dumpMemeryWithWidth(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')) + 8, 5)
       
    def hook_mem_read_unmapped_1817209B0(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        self.emu.log_backtrace()
    def hook_mem_read_unmapped_18004B850(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        # self.emu.dump_memory_with_width(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')), 5)
        # self.emu.log_backtrace()
    def hook_mem_read_unmapped_1800A6480(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.dumpMemeryWithWidth(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')), 6)
        self.dumpMemeryWithWidth(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')), 6)
        uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X1'), 0x50000)
        uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X2'), 0x403)

    
    
    def hook_mem_read_unmapped_1C6ABB7D0(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x}:0x{int.from_bytes(uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')),8), byteorder=self.emu.endian):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        # uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X1'), 0x50000)
        # uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X2'), 0x403)
    def hook_mem_read_unmapped_1C6ABB9E0(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x}:0x{int.from_bytes(uc.mem_read(uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')),8), byteorder=self.emu.endian):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X1'), 0x403)
        uc.reg_write(getattr(arm64_const, f'UC_ARM64_REG_X2'), 0x402)

    def hook_mem_read_unmapped_100009274(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.emu.log_backtrace()

    def hook_mem_read_unmapped_100008194(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.emu.log_backtrace()
        
    def hook_mem_read_unmapped_100008148(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.emu.log_backtrace()

    def hook_mem_read_unmapped_10276A708(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.emu.log_backtrace()
        
    def hook_mem_to_print_log_backtrace(self, uc, address: int, size: int, user_data: dict):
        print(f"[core.py] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
            f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
            f"x2 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
            f"x30 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")
        self.emu.log_backtrace()
    def hook_mem_to_print_all_reg(self, uc, address: int, size: int, user_data: dict):
        print(f"[错误] 尝试读取未映射内存：地址=0x{address:x}, 大小={size}字节")
        print(f"x0 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X0')):x} "
        f"x1 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X1')):x} "
        f"x2 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X2')):x} "
        f"x3 {uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X3')):x} "
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
        f"x26 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X26')):x} "
        f"x30 0x{uc.reg_read(getattr(arm64_const, f'UC_ARM64_REG_X30')):x}")  

    def resolve_modules(self, module_names: List[str]):
        """Load system modules if don't loaded."""
        fixup = SystemModuleFixup(self.emu)

        # resolve modules memery
        # self.map_all_modules(module_names)
        # print(f"resolve_modules 1 {self.emu.uc.mem_read(0x1AB4758C4,4)} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")

        # print(f"resolve_modules resolve_modules")
        
        # self.emu.add_hook(0x193E27EAC, self.hook_mem_read_unmapped) #_load_images start
        # self.emu.add_hook(0x193E28520, self.hook_mem_read_unmapped) #_load_images end 1
        # self.emu.add_hook(0x193E28500, self.hook_mem_read_unmapped) #_load_images end
        # self.emu.add_hook(0x193E27F1C, self.hook_mem_read_unmapped) #_load_images ime 1

        # self.emu.add_hook(0x193E27F34, self.hook_mem_read_unmapped) #_load_images ime 2
        # self.emu.add_hook(0x193E27F04, self.hook_mem_read_unmapped) #_load_images ime 3
        # self.emu.add_hook(0x193E27F94, self.hook_mem_read_unmapped) #_load_images ime 4
        # self.emu.add_hook(0x193E27FB4, self.hook_mem_read_unmapped) #_load_images ime 5
        # self.emu.add_hook(0x193E27FCC, self.hook_mem_read_unmapped) #_load_images ime 6
        # self.emu.add_hook(0x193E27FE4, self.hook_mem_read_unmapped) #_load_images ime 7
        # self.emu.add_hook(0x193E28020, self.hook_mem_read_unmapped) #_load_images ime 8
        # self.emu.add_hook(0x193E28064, self.hook_mem_read_unmapped) #_load_images ime 9
        # self.emu.add_hook(0x193E2808C, self.hook_mem_read_unmapped) #_load_images ime 10
        # self.emu.add_hook(0x193E280A4, self.hook_mem_read_unmapped) #_load_images ime 11
        # self.emu.add_hook(0x193E280B8, self.hook_mem_read_unmapped) #_load_images ime 12
        # self.emu.add_hook(0x193E280C0, self.hook_mem_read_unmapped) #_load_images ime 13
        # self.emu.add_hook(0x193E280D0, self.hook_mem_read_unmapped) #_load_images ime 14
        # self.emu.add_hook(0x193E28194, self.hook_mem_read_unmapped) #_load_images ime 15
        # self.emu.add_hook(0x193E281C0, self.hook_mem_read_unmapped) #_load_images ime 16
        # self.emu.add_hook(0x193E281D4, self.hook_mem_read_unmapped) #_load_images ime 17
        # self.emu.add_hook(0x193E2822C, self.hook_mem_read_unmapped) #_load_images ime 18
        # self.emu.add_hook(0x193E282A4, self.hook_mem_read_unmapped) #_load_images ime 19
        # self.emu.add_hook(0x193E28264, self.hook_mem_read_unmapped) #_load_images ime 20
        # self.emu.add_hook(0x193E28278, self.hook_mem_read_unmapped) #_load_images ime 21
        # self.emu.add_hook(0x193E2828C, self.hook_mem_read_unmapped) #_load_images ime 22
        # self.emu.add_hook(0x193E28298, self.hook_mem_read_unmapped) #_load_images ime 23
        # self.emu.add_hook(0x193E282B0, self.hook_mem_read_unmapped) #_load_images ime 24
        # self.emu.add_hook(0x193E282BC, self.hook_mem_read_unmapped) #_load_images ime 25
        # self.emu.add_hook(0x193E282C8, self.hook_mem_read_unmapped) #_load_images ime 26
        # self.emu.add_hook(0x193E28258, self.hook_mem_read_unmapped) #_load_images ime 27

        # self.emu.add_hook(0x193E2E48C, self.hook_mem_read_unmapped)
        # self.emu.add_hook(0x193E2E490, self.hook_mem_read_unmapped) #_load_images ime 28
        # self.emu.add_hook(0x193E2E494, self.hook_mem_read_unmapped) #_load_images ime 28
        # self.emu.add_hook(0x193E2E500, self.hook_mem_read_unmapped) #_load_images ime 29
        # self.emu.add_hook(0x193E2E51C, self.hook_mem_read_unmapped) #_load_images ime 30
       
        # self.emu.add_hook(0x18046FF18, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 31
        # self.emu.add_hook(0x18046FB44, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 32
        # self.emu.add_hook(0x18046FE20, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 33
        # self.emu.add_hook(0x18046FB78, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 34
        # self.emu.add_hook(0x18046FE20, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 35
        # self.emu.add_hook(0x18046FB90, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 36
        # self.emu.add_hook(0x18046FBA4, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 37
        # self.emu.add_hook(0x18046FC38, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 38
        # self.emu.add_hook(0x18046FD60, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 39
        # self.emu.add_hook(0x18046FFC8, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 40
        # self.emu.add_hook(0x180470004, self.hook_mem_read_unmapped) #_load_images  ____forwarding___ 41
        # self.emu.add_hook(0x180470014, self.hook_mem_read_unmapped_180470014) #_load_images  ____forwarding___ 42

        modules = []
        for module_name in module_names:
            if self.emu.find_module(module_name):
                continue

            module_file = self.search_module_binary(module_name)
            module = self.emu.load_module(
                module_file=module_file,
                exec_objc_init=False,
            )
            modules.append(module)
            # if module_name == "libdispatch.dylib":
            #     self.emu.add_hook(0x193E1A460, self.hook_mem_read_unmapped)
            if module_name == "libsystem_platform.dylib":
                print(f"Loading libsystem_platform.dylib - MMIO region already initialized")
                
                # 验证MMIO区域初始化
                # self.debug_mmio_region()

                # self.emu.add_hook(0x18038A1A0, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18038A180, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18038A114, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18038A65C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18EE8E99C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18044C788, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18044C768, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18044C8CC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18044C894, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x189118C24, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x189118C64, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x189118CBC, self.hook_mem_read_unmapped)

                # self.emu.add_hook(0x1AB48EEBC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1AB48EDF8, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1800A627C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1800A6280, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18007F0B8, self.hook_mem_read_unmapped_callStack)
                # self.emu.add_hook(0x1803DA0D0, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803DA0D4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180077CD4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x181760BD0, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1800A6288, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180077D10, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803D9F98, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803D9FC8, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803D9FDC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1AB49A8E4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1AB4994D4, self.hook_mem_read_unmapped_1AB4994D4)
                # self.emu.add_hook(0x1803F0E50, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803F0E54, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1803F0E58, self.hook_mem_read_unmapped)
                
                # self.emu.add_hook(0x1803F0EAC, self.hook_mem_read_unmapped)
                
                # self.emu.add_hook(0x181725E3C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x181725E40, self.hook_mem_read_unmapped)

                # self.emu.add_hook(0x18040C094, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18040C0EC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18040C0C4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18040C0D0, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1804275F0, self.hook_mem_read_unmapped)

                # self.emu.add_hook(0x18042762C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427640, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427644, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427654, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427658, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1804276B0, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1804276E8, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427740, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x180427950, self.hook_mem_read_unmapped) 
                # self.emu.add_hook(0x180427934, self.hook_mem_read_unmapped)

                # self.emu.add_hook(0x1C6ABB7F0, self.hook_mem_read_unmapped_1C6ABB7F0)
                # self.emu.add_hook(0x1817209EC, self.hook_mem_read_unmapped_1817209EC)
                # self.emu.add_hook(0x1817209B0, self.hook_mem_read_unmapped_1817209B0)
                # self.emu.add_hook(0x1C6ABB7C4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1C6ABB7C8, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1817209D4, self.hook_mem_read_unmapped_1817209D4)
                # self.emu.add_hook(0x1C6ABB86C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18004B850, self.hook_mem_read_unmapped_18004B850)
                # self.emu.add_hook(0x18171D408, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18171C908, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18171D1DC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18171D3C4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18004C650, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x18007FE10, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1800A6480, self.hook_mem_read_unmapped_1800A6480)
                # self.emu.add_hook(0x1C6ABB9E0, self.hook_mem_read_unmapped_1C6ABB9E0)
                # self.emu.add_hook(0x1C6ABB7D0, self.hook_mem_read_unmapped_1C6ABB7D0)

                # objc.A.dylib sendmsg
                # self.emu.add_hook(0x193E1A49C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E1A4F8, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E1A494, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E1A540, self.hook_mem_read_unmapped)
                
                # self.emu.add_hook(0x188FBA178, self.hook_mem_read_unmapped)
                
                # self.emu.add_hook(0x100D01D20, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x100009274, self.hook_mem_read_unmapped_100009274)
                # self.emu.add_hook(0x100008194, self.hook_mem_read_unmapped_100008194)
                # self.emu.add_hook(0x100008148, self.hook_mem_read_unmapped_100008148)

                # self.emu.add_hook(0x10276A708, self.hook_mem_read_unmapped_10276A708)   
                # self.emu.add_hook(0x100D01B08, self.hook_mem_to_print_log_backtrace)

                # self.emu.add_hook(0x1C6A4D8B0, self.hook_mem_to_print_all_reg)
                # self.emu.add_hook(0x1C6A4D8B4, self.hook_mem_to_print_all_reg)

                # self.emu.add_hook(0x100036330, self.hook_mem_to_print_all_reg)
                # self.emu.add_hook(0x100036340, self.hook_mem_to_print_all_reg)
                # self.emu.add_hook(0x10003655C, self.hook_mem_to_print_all_reg)

                # self.emu.add_hook(0x193E23D8C, self.hook_mem_to_print_all_reg)
                

                # self.emu.add_hook(0x193E37054, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1C6AD18BC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x1C6AD1894, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37060, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E3706C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37068, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37070, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E3707C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37080, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E370A4, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E370AC, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37074, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37118, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37114, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37174, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E3762C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E3717C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37200, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37124, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37148, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E3714C, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37150, self.hook_mem_read_unmapped)
                # self.emu.add_hook(0x193E37154, self.hook_mem_read_unmapped)
               
            # self._init_bss_section(module)
            # print(f"resolve_modules 2 {self.emu.uc.mem_read(0x1AB4758C4,4)} {self.emu.uc.mem_read(0xFFFFFC025,4)} {self.emu.uc.mem_read(0x1D610141C,4)}")
            # Fixup must be executed before initializing Objective-C.
            # fixup.install(module)
            
        for module_name in module_names:
            self._after_module_loaded(module_name)
            
        for module in modules:

            self.init_objc(module) #Foundation之后hook失败

            module.binary = None

        
        

    def _init_bss_section(self, module: Module):
        """Initialize BSS segment for the module."""
        if not module.binary:
            print(f"_init_bss_section: module.binary is None for {module.name}")
            return

        print(f"_init_bss_section: processing module {module.name}")
        print(f"_init_bss_section: available segments: {[seg.name for seg in module.binary.segments]}")
        
        # 查找__bss段
        bss_section = None
        for segment in module.binary.segments:
            if segment.name in ["__DATA", "__DATA_DIRTY"]:
                for section in segment.sections:
                    if section.name == "__bss":
                        bss_section = section
                        if bss_section:
                            print(f"_init_bss_section: found __bss segment - virtual_address: 0x{bss_section.virtual_address:x}, size: {bss_section.size}")
                            self.emu.write_zeros(bss_section.virtual_address, bss_section.size)

        if module.name == "UIKitCore":
            print(f"UIKitCore 0x1D616ED08:{self.emu.uc.mem_read(0x1D616ED08,8)}")
            
    def _after_module_loaded(self, module_name: str):
        print(f"_after_module_loaded module_name: {module_name}")
        """Perform initialization after module loaded."""
        print(f"0x1D6101370:0x{int.from_bytes(self.emu.uc.mem_read(0x1D6101370, 8), byteorder=self.emu.endian):x}")
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

        self._init_lib_xpc()

        # Call initialize function of `CoreFoundation`
        self.emu.call_symbol("___CFInitialize")

        is_cf_prefs_d = self.emu.find_symbol("_isCFPrefsD")
        self.emu.write_u8(is_cf_prefs_d.address, 1)

        # Call initialize function of `Foundation`
        self.emu.call_symbol("__NSInitializePlatform")

        # self.fix_method_signature_rom_table()

        amkrtemp_sentinel = self.emu.find_symbol("__amkrtemp.sentinel")
        # print(f"amkrtemp_sentinel {amkrtemp_sentinel}")
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
        print(f"table {table}")

        for index, item in enumerate(table_data):
            offset = table.address + index * 24
            str_ptr = self.emu.create_string(item[1])

            # print(f"offset 0x{offset + 8:x} {str_ptr} {item[2]}")
            self.emu.write_pointer(offset + 8, str_ptr)
            self.emu.write_u64(offset + 16, item[2])
        for i in range(0, 100):
            print(f"table.address 0x{table.address + i * 8:x}:0x{self.emu.read_u64(table.address + i * 8):x}")
        

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

        ALL_MODULES = OBJC_DEPENDENCIES + UI_KIT_DEPENDENCIES + ONLY_MAP
        self.map_all_modules(ALL_MODULES)

        print(f"self._dyld_image_info {self._dyld_image_info}")
        # symbol_dataSegmentsRanges = self.emu.find_symbol("_dataSegmentsRanges")
        # print(f"symbol_dataSegmentsRanges {symbol_dataSegmentsRanges}")
        self.emu.write_u64(0x1D6103F38, 0x180000000)
        self.emu.write_u64(0x1D6103F38 + 8, 0x1E7BA4000)
        self.emu.write_u64(0x1D61759D0, 0x18905E1D4)
        #__int64 __fastcall cache_t::eraseNolock(cache_t *__hidden this, const char *)
        # 直接return,该函数会调用task_threads，导致BRK
        self.emu.write_u64(0x193E1CB88, 0xD65F03C0) # ret

        if self.emu.enable_objc:
            self._enable_objc()

        if self.emu.enable_ui_kit:
            self._enable_ui_kit()

        self._setup_standard_io()
