from __future__ import annotations

import ctypes
import os
import random
import time
from functools import wraps
from typing import Dict, TYPE_CHECKING

from unicorn import arm64_const

from chomper.exceptions import SystemOperationFailed, ProgramTerminated
from chomper.os.base import SyscallError
from chomper.typing import SyscallHandleCallable
from chomper.utils import struct_to_bytes, bytes_to_struct, to_signed

from . import const
from .structs import Rusage, MachMsgHeaderT, NDRRecordT, ReplayFmtT
from .sysctl import sysctl, sysctlbyname
if TYPE_CHECKING:
    from chomper.core import Chomper

SYSCALL_MAP: Dict[int, str] = {
    const.SYS_EXIT: "SYS_exit",
    const.SYS_READ: "SYS_read",
    const.SYS_WRITE: "SYS_write",
    const.SYS_OPEN: "SYS_open",
    const.SYS_CLOSE: "SYS_close",
    const.SYS_LINK: "SYS_link",
    const.SYS_UNLINK: "SYS_unlink",
    const.SYS_CHDIR: "SYS_chdir",
    const.SYS_FCHDIR: "SYS_fchdir",
    const.SYS_CHMOD: "SYS_chmod",
    const.SYS_CHOWN: "SYS_chown",
    const.SYS_GETPID: "SYS_getpid",
    const.SYS_GETUID: "SYS_getuid",
    const.SYS_GETEUID: "SYS_geteuid",
    const.SYS_KILL: "SYS_kill",
    const.SYS_ACCESS: "SYS_access",
    const.SYS_CHFLAGS: "SYS_chflags",
    const.SYS_FCHFLAGS: "SYS_fchflags",
    const.SYS_GETPPID: "SYS_getppid",
    const.SYS_PIPE: "SYS_pipe",
    const.SYS_GETEGID: "SYS_getegid",
    const.SYS_SIGACTION: "SYS_sigaction",
    const.SYS_SIGPROCMASK: "SYS_sigprocmask",
    const.SYS_SIGALTSTACK: "SYS_sigaltstack",
    const.SYS_IOCTL: "SYS_ioctl",
    const.SYS_SYMLINK: "SYS_symlink",
    const.SYS_READLINK: "SYS_readlink",
    const.SYS_MUNMAP: "SYS_munmap",
    const.SYS_MADVISE: "SYS_madvise",
    const.SYS_FCNTL: "SYS_fcntl",
    const.SYS_FSYNC: "SYS_fsync",
    const.SYS_SOCKET: "SYS_socket",
    const.SYS_SIGSUSPEND: "SYS_sigsuspend",
    const.SYS_GETTIMEOFDAY: "SYS_gettimeofday",
    const.SYS_GETRUSAGE: "SYS_getrusage",
    const.SYS_READV: "SYS_readv",
    const.SYS_WRITEV: "SYS_writev",
    const.SYS_FCHOWN: "SYS_fchown",
    const.SYS_FCHMOD: "SYS_fchmod",
    const.SYS_RENAME: "SYS_rename",
    const.SYS_MKDIR: "SYS_mkdir",
    const.SYS_RMDIR: "SYS_rmdir",
    const.SYS_ADJTIME: "SYS_adjtime",
    const.SYS_PREAD: "SYS_pread",
    const.SYS_QUOTACTL: "SYS_quotactl",
    const.SYS_CSOPS: "SYS_csops",
    const.SYS_CSOPS_AUDITTOKEN: "SYS_csops_audittoken",
    const.SYS_RLIMIT: "SYS_rlimit",
    const.SYS_SETRLIMIT: "SYS_setrlimit",
    const.SYS_MMAP: "SYS_mmap",
    const.SYS_LSEEK: "SYS_lseek",
    const.SYS_SYSCTL: "SYS_sysctl",
    const.SYS_OPEN_DPROTECTED_NP: "SYS_open_dprotected_np",
    const.SYS_GETATTRLIST: "SYS_getattrlist",
    const.SYS_SETXATTR: "SYS_setxattr",
    const.SYS_FSETXATTR: "SYS_fsetxattr",
    const.SYS_LISTXATTR: "SYS_listxattr",
    const.SYS_SHM_OPEN: "SYS_shm_open",
    const.SYS_SYSCTLBYNAME: "SYS_sysctlbyname",
    const.SYS_GETTID: "SYS_gettid",
    const.SYS_IDENTITYSVC: "SYS_identitysvc",
    const.SYS_PSYNCH_MUTEXWAIT: "SYS_psynch_mutexwait",
    const.SYS_ISSETUGID: "SYS_issetugid",
    const.SYS_PTHREAD_SIGMASK: "SYS_pthread_sigmask",
    const.SYS_PROC_INFO: "SYS_proc_info",
    const.SYS_STAT64: "SYS_stat64",
    const.SYS_FSTAT64: "SYS_fstat64",
    const.SYS_LSTAT64: "SYS_lstat64",
    const.SYS_GETDIRENTRIES64: "SYS_getdirentries64",
    const.SYS_STATFS64: "SYS_statfs64",
    const.SYS_FSTATFS64: "SYS_fstatfs64",
    const.SYS_FSSTAT64: "SYS_fsstat64",
    const.SYS_BSDTHREAD_CREATE: "SYS_bsdthread_create",
    const.SYS_LCHOWN: "SYS_lchown",
    const.SYS_MAC_SYSCALL: "SYS_mac_syscall",
    const.SYS_READ_NOCANCEL: "SYS_read_nocancel",
    const.SYS_WRITE_NOCANCEL: "SYS_write_nocancel",
    const.SYS_OPEN_NOCANCEL: "SYS_open_nocancel",
    const.SYS_CLOSE_NOCANCEL: "SYS_close_nocancel",
    const.SYS_FCNTL_NOCANCEL: "SYS_fcntl_nocancel",
    const.SYS_FSYNC_NOCANCEL: "SYS_fsync_nocancel",
    const.SYS_READV_NOCANCEL: "SYS_readv_nocancel",
    const.SYS_WRITEV_NOCANCEL: "SYS_writev_nocancel",
    const.SYS_PREAD_NOCANCEL: "SYS_pread_nocancel",
    const.SYS_MWAIT_SIGNAL_NOCANCEL: "SYS_mwait_signal_nocancel",
    const.SYS_GETATTRLISTBULK: "SYS_getattrlistbulk",
    const.SYS_OPENAT: "SYS_openat",
    const.SYS_OPENAT_NOCANCEL: "SYS_openat_nocancel",
    const.SYS_RENAMEAT: "SYS_renameat",
    const.SYS_FACCESSAT: "SYS_faccessat",
    const.SYS_FCHMODAT: "SYS_fchmodat",
    const.SYS_FCHOWNAT: "SYS_fchownat",
    const.SYS_FSTATAT64: "SYS_fstatat64",
    const.SYS_LINKAT: "SYS_linkat",
    const.SYS_UNLINKAT: "SYS_unlinkat",
    const.SYS_READLINKAT: "SYS_readlinkat",
    const.SYS_SYMLINKAT: "SYS_symlinkat",
    const.SYS_MKDIRAT: "SYS_mkdirat",
    const.SYS_BSDTHREAD_CTL: "SYS_bsdthread_ctl",
    const.SYS_GETENTROPY: "SYS_getentropy",
    const.SYS_ULOCK_WAIT: "SYS_ulock_wait",
    const.SYS_ULOCK_WAKE: "SYS_ulock_wake",
    const.SYS_TERMINATE_WITH_PAYLOAD: "SYS_terminate_with_payload",
    const.SYS_ABORT_WITH_PAYLOAD: "SYS_abort_with_payload",
    const.SYS_PREADV: "SYS_preadv",
    const.SYS_PREADV_NOCANCEL: "SYS_preadv_nocancel",
    const.MACH_ABSOLUTE_TIME_TRAP: "MACH_ABSOLUTE_TIME_TRAP",
    const.KERNELRPC_MACH_VM_ALLOCATE_TRAP: "KERNELRPC_MACH_VM_ALLOCATE_TRAP",
    const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP: "KERNELRPC_MACH_VM_DEALLOCATE_TRAP",
    const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP: "KERNELRPC_MACH_PORT_ALLOCATE_TRAP",
    const.KERNELRPC_MACH_PORT_DEALLOCATE_TRAP: "KERNELRPC_MACH_PORT_DEALLOCATE_TRAP",
    const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP: (
        "KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP"
    ),
    const.KERNELRPC_MACH_VM_PROTECT_TRAP: "KERNELRPC_MACH_VM_PROTECT_TRAP",
    const.KERNELRPC_MACH_VM_MAP_TRAP: "KERNELRPC_MACH_VM_MAP_TRAP",
    const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP: "KERNELRPC_MACH_PORT_CONSTRUCT_TRAP",
    const.MACH_REPLY_PORT_TRAP: "MACH_REPLY_PORT_TRAP",
    const.TASK_SELF_TRAP: "TASK_SELF_TRAP",
    const.HOST_SELF_TRAP: "HOST_SELF_TRAP",
    const.MACH_MSG_TRAP: "MACH_MSG_TRAP",
    const.SWTCH_PRI: "SWTCH_PRI",
    const.KERNELRPC_MACH_PORT_TYPE_TRAP: "KERNELRPC_MACH_PORT_TYPE_TRAP",
    const.MACH_TIMEBASE_INFO_TRAP: "MACH_TIMEBASE_INFO_TRAP",
    const.MK_TIMER_CREATE_TRAP: "MK_TIMER_CREATE_TRAP",
}

ERROR_MAP = {
    SyscallError.EPERM: (const.EPERM, "EPERM"),
    SyscallError.ENOENT: (const.ENOENT, "ENOENT"),
    SyscallError.EBADF: (const.EBADF, "EBADF"),
    SyscallError.EACCES: (const.EACCES, "EACCES"),
    SyscallError.ENOTDIR: (const.ENOTDIR, "ENOTDIR"),
}

syscall_handlers: Dict[int, SyscallHandleCallable] = {}


def get_syscall_handlers() -> Dict[int, SyscallHandleCallable]:
    """Get the default system call handlers."""
    return syscall_handlers.copy()


def register_syscall_handler(syscall_no: int):
    """Decorator to register a system call handler."""

    def wrapper(f):
        @wraps(f)
        def decorator(emu: Chomper):
            retval = -1
            error_type = None

            try:
                retval = f(emu)
            except (FileNotFoundError, PermissionError):
                error_type = SyscallError.ENOENT
            except SystemOperationFailed as e:
                error_type = e.error_type

            if error_type in ERROR_MAP:
                error_no, error_name = ERROR_MAP[error_type]

                emu.logger.info(f"Set errno {error_name}({error_no})")
                emu.os.errno = error_no

            # Clear the carry flag after called, many functions will
            # check it after system calls.
            nzcv = emu.uc.reg_read(arm64_const.UC_ARM64_REG_NZCV)
            emu.uc.reg_write(arm64_const.UC_ARM64_REG_NZCV, nzcv & ~(1 << 29))

            return retval

        syscall_handlers[syscall_no] = decorator
        return f

    return wrapper


def permission_denied():
    raise SystemOperationFailed("No permission", SyscallError.EPERM)


@register_syscall_handler(const.SYS_EXIT)
def handle_sys_exit(emu: Chomper):
    status = emu.get_arg(0)

    raise ProgramTerminated("Program terminated with status: %s" % status)


@register_syscall_handler(const.SYS_READ)
@register_syscall_handler(const.SYS_READ_NOCANCEL)
def handle_sys_read(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    data = emu.os.read(fd, size)
    emu.write_bytes(buf, data)

    return len(data)


@register_syscall_handler(const.SYS_WRITE)
@register_syscall_handler(const.SYS_WRITE_NOCANCEL)
def handle_sys_write(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.os.write(fd, buf, size)


@register_syscall_handler(const.SYS_OPEN)
@register_syscall_handler(const.SYS_OPEN_NOCANCEL)
def handle_sys_open(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(2)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_CLOSE)
@register_syscall_handler(const.SYS_CLOSE_NOCANCEL)
def handle_sys_close(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.close(fd)

    return 0


@register_syscall_handler(const.SYS_LINK)
def handle_sys_link(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.link(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINK)
def handle_sys_unlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.unlink(path)

    return 0


@register_syscall_handler(const.SYS_CHDIR)
def handle_sys_chdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.chdir(path)

    return 0


@register_syscall_handler(const.SYS_FCHDIR)
def handle_sys_fchdir(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fchdir(fd)

    return 0


@register_syscall_handler(const.SYS_CHMOD)
def handle_sys_chmod(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.chmod(path, mode)

    return 0


@register_syscall_handler(const.SYS_CHOWN)
def handle_sys_chown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.chown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_GETPID)
def handle_sys_getpid(emu: Chomper):
    return emu.os.pid


@register_syscall_handler(const.SYS_GETUID)
def handle_sys_getuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_GETEUID)
def handle_sys_geteuid(emu: Chomper):
    return emu.os.uid


@register_syscall_handler(const.SYS_KILL)
def handle_sys_kill(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_ACCESS)
def handle_sys_access(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    if not emu.os.access(path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_CHFLAGS)
def handle_sys_chflags(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_FCHFLAGS)
def handle_sys_fchflags(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_GETPPID)
def handle_sys_getppid(emu: Chomper):
    return 1


@register_syscall_handler(const.SYS_PIPE)
def handle_sys_pipe(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SIGACTION)
def handle_sys_sigaction(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGPROCMASK)
def handle_sys_sigprocmask(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SIGALTSTACK)
def handle_sys_sigaltstack(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_IOCTL)
def handle_sys_ioctl(emu: Chomper):
    fd = emu.get_arg(0)
    req = emu.get_arg(1)

    inout = req & ~((0x3FFF << 16) | 0xFF00 | 0xFF)
    group = (req >> 8) & 0xFF
    num = req & 0xFF
    length = (req >> 16) & 0x3FFF

    emu.logger.info(
        f"Recv ioctl request: fd={fd}, inout={hex(inout)}, group='{chr(group)}', "
        f"num={num}, length={length}"
    )

    emu.logger.warning("ioctl request not processed")
    return 0


@register_syscall_handler(const.SYS_SYMLINK)
def handle_sys_symlink(emu: Chomper):
    src_path = emu.read_string(emu.get_arg(0))
    dst_path = emu.read_string(emu.get_arg(1))

    emu.os.symlink(src_path, dst_path)

    return 0


@register_syscall_handler(const.SYS_READLINK)
def handle_sys_readlink(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    buf = emu.get_arg(1)
    buf_size = emu.get_arg(2)

    result = emu.os.readlink(path)
    if result is None or len(result) > buf_size:
        return -1

    emu.write_string(buf, result)

    return 0


@register_syscall_handler(const.SYS_MUNMAP)
def handle_sys_munmap(emu: Chomper):
    addr = emu.get_arg(0)

    emu.free(addr)

    return 0


@register_syscall_handler(const.SYS_MADVISE)
def handle_sys_madvise(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_GETEGID)
def handle_sys_getegid(emu: Chomper):
    return 1


@register_syscall_handler(const.SYS_GETTIMEOFDAY)
def handle_sys_gettimeofday(emu: Chomper):
    tv = emu.get_arg(0)

    result = emu.os.gettimeofday()
    emu.write_bytes(tv, result)

    return 0


@register_syscall_handler(const.SYS_GETRUSAGE)
def handle_sys_getrusage(emu: Chomper):
    r = emu.get_arg(1)

    rusage = Rusage()
    emu.write_bytes(r, struct2bytes(rusage))

    return 0


@register_syscall_handler(const.SYS_READV)
@register_syscall_handler(const.SYS_READV_NOCANCEL)
def handle_sys_readv(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        data = emu.os.read(fd, iov_len)
        emu.write_bytes(iov_base, data)

        result += len(data)

        if len(data) != iov_len:
            break

        iov += 16

    return result


@register_syscall_handler(const.SYS_WRITEV)
@register_syscall_handler(const.SYS_WRITEV_NOCANCEL)
def handle_sys_writev(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        write_len = emu.os.write(fd, iov_base, iov_len)
        result += write_len

        if write_len != iov_len:
            break

        iov += 16

    return result


@register_syscall_handler(const.SYS_FCHOWN)
def handle_sys_fchown(emu: Chomper):
    fd = emu.get_arg(0)
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.fchown(fd, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FCHMOD)
def handle_sys_fchmod(emu: Chomper):
    fd = emu.get_arg(0)
    mode = emu.get_arg(1)

    emu.os.fchmod(fd, mode)

    return 0


@register_syscall_handler(const.SYS_RENAME)
def handle_sys_rename(emu: Chomper):
    old = emu.read_string(emu.get_arg(0))
    new = emu.read_string(emu.get_arg(1))

    emu.os.rename(old, new)

    return 0


@register_syscall_handler(const.SYS_MKDIR)
def handle_sys_mkdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    mode = emu.get_arg(1)

    emu.os.mkdir(path, mode)

    return 0


@register_syscall_handler(const.SYS_RMDIR)
def handle_sys_rmdir(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))

    emu.os.rmdir(path)

    return 0


@register_syscall_handler(const.SYS_ADJTIME)
def handle_sys_adjtime(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_PREAD)
@register_syscall_handler(const.SYS_PREAD_NOCANCEL)
def handle_sys_pread(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    size = emu.get_arg(2)
    offset = emu.get_arg(3)

    data = emu.os.pread(fd, size, offset)
    emu.write_bytes(buf, data)

    return len(data)

@register_syscall_handler(const.SYS_MWAIT_SIGNAL_NOCANCEL)
def handle_sys_mwait_signal_nocancel(emu: Chomper):
    """
    Handle SYS_MWAIT_SIGNAL_NOCANCEL system call.
    
    This system call waits for a signal without allowing cancellation.
    It's typically used for thread synchronization in iOS/macOS.
    
    Args:
        emu: The Chomper emulator instance
        
    Returns:
        int: 0 on success, -1 on error
    """
    # Get system call arguments
    # x0: signal - signal number to wait for
    # x1: timeout - timeout value (optional)
    # x2: flags - additional flags (optional)
    
    signal = emu.get_arg(0)
    timeout = emu.get_arg(1)
    flags = emu.get_arg(2)
    
    emu.logger.info(f"mwait_signal_nocancel: signal={signal}, timeout={timeout}, flags={flags}")
    
    # In a real implementation, this would:
    # 1. Block the current thread until the specified signal is received
    # 2. Handle timeout if specified
    # 3. Process any additional flags
    
    # For simulation purposes, we'll just log the call and return success
    # In a real emulator, you might want to:
    # - Track signal state
    # - Implement actual waiting behavior
    # - Handle timeout mechanisms
    
    emu.logger.info("mwait_signal_nocancel: Signal wait completed (simulated)")
    
    return 0


@register_syscall_handler(const.SYS_QUOTACTL)
def handle_sys_quotactl(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_CSOPS)
def handle_sys_csops(emu: Chomper):
    useraddr = emu.get_arg(2)
    emu.write_u32(useraddr, 0x4000800)

    return 0


@register_syscall_handler(const.SYS_CSOPS_AUDITTOKEN)
def handle_sys_csops_audittoken(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_RLIMIT)
def handle_sys_rlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SETRLIMIT)
def handle_sys_setrlimit(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_MMAP)
def handle_sys_mmap(emu: Chomper):
    length = emu.get_arg(1)
    fd = to_signed(emu.get_arg(4), 4)
    offset = emu.get_arg(5)

    buf = emu.create_buffer(length)

    if fd != -1:
        chunk_size = 1024 * 1024
        content = b""

        while True:
            chunk = os.read(fd, chunk_size)
            if not chunk:
                break
            content += chunk

        emu.write_bytes(buf, content[offset:])

    return buf


@register_syscall_handler(const.SYS_LSEEK)
def handle_sys_lseek(emu: Chomper):
    fd = emu.get_arg(0)
    offset = emu.get_arg(1)
    whence = emu.get_arg(2)

    offset = to_signed(offset, 8)

    return emu.os.lseek(fd, offset, whence)


@register_syscall_handler(const.SYS_FSYNC)
@register_syscall_handler(const.SYS_FSYNC_NOCANCEL)
def handle_sys_fsync(emu: Chomper):
    fd = emu.get_arg(0)

    emu.os.fsync(fd)

    return 0


@register_syscall_handler(const.SYS_SOCKET)
def handle_sys_socket(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SIGSUSPEND)
def handle_sys_sigsuspend(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_FCNTL)
@register_syscall_handler(const.SYS_FCNTL_NOCANCEL)
def handle_sys_fcntl(emu: Chomper):
    fd = emu.get_arg(0)
    cmd = emu.get_arg(1)
    arg = emu.get_arg(2)

    if cmd == const.F_GETFL:
        if fd in (emu.os.stdin,):
            return os.O_RDONLY
        elif fd in (emu.os.stdout, emu.os.stderr):
            return os.O_WRONLY
    elif cmd == const.F_GETPATH:
        path = emu.os.get_dir_path(fd)
        if path:
            emu.write_string(arg, path)
    else:
        emu.logger.warning(f"Unhandled fcntl command: {cmd}")

    return 0


@register_syscall_handler(const.SYS_SYSCTL)
def handle_sys_sysctl(emu: Chomper):
    name = emu.get_arg(0)
    oldp = emu.get_arg(2)

    ctl_type = emu.read_u32(name)
    ctl_ident = emu.read_u32(name + 4)

    result = sysctl(ctl_type, ctl_ident)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {ctl_type}, {ctl_ident}")
        return -1

    if isinstance(result, ctypes.Structure):
        emu.write_bytes(oldp, struct2bytes(result))
    elif isinstance(result, str):
        emu.write_string(oldp, result)
    elif isinstance(result, int):
        emu.write_u64(oldp, result)

    return 0


@register_syscall_handler(const.SYS_OPEN_DPROTECTED_NP)
def handle_sys_open_dprotected_np(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    flags = emu.get_arg(1)
    mode = emu.get_arg(4)

    return emu.os.open(path, flags, mode)


@register_syscall_handler(const.SYS_GETATTRLIST)
def handle_sys_getattrlist(emu: Chomper):
    return -1


@register_syscall_handler(const.SYS_SETXATTR)
def handle_sys_setxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_FSETXATTR)
def handle_sys_fsetxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_LISTXATTR)
def handle_sys_listxattr(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_SHM_OPEN)
def handle_sys_shm_open(emu: Chomper):
    return 0x80000000


@register_syscall_handler(const.SYS_SYSCTLBYNAME)
def handle_sys_sysctlbyname(emu: Chomper):
    name = emu.read_string(emu.get_arg(0))
    oldp = emu.get_arg(2)
    oldlenp = emu.get_arg(3)

    if not oldp or not oldlenp:
        return 0

    result = sysctlbyname(name)
    if result is None:
        emu.logger.warning(f"Unhandled sysctl command: {name}")
        return -1

    if isinstance(result, ctypes.Structure):
        emu.write_bytes(oldp, struct2bytes(result))
    elif isinstance(result, str):
        emu.write_string(oldp, result)
    elif isinstance(result, int):
        emu.write_u64(oldp, result)

    return 0


@register_syscall_handler(const.SYS_GETTID)
def handle_sys_gettid(emu: Chomper):
    return 1000


@register_syscall_handler(const.SYS_IDENTITYSVC)
def handle_sys_identitysvc(emu: Chomper):
    permission_denied()


@register_syscall_handler(const.SYS_PSYNCH_MUTEXWAIT)
def handle_sys_psynch_mutexwait(emu: Chomper):
    """
    Handle SYS_PSYNCH_MUTEXWAIT system call.
    
    This system call waits for a mutex to become available.
    To prevent infinite loops, we implement a timeout mechanism.
    
    Args:
        emu: The Chomper emulator instance
        
    Returns:
        int: 0 on success, -1 on error
    """
    # Get system call arguments
    # x0: mutex - pointer to mutex structure
    # x1: timeout - timeout value (optional)
    # x2: flags - additional flags (optional)
    
    mutex_ptr = emu.get_arg(0)
    timeout = emu.get_arg(1)
    flags = emu.get_arg(2)
    
    # 防止无限循环的机制
    # 1. 检查是否已经等待过这个mutex
    if not hasattr(emu, '_mutex_wait_count'):
        emu._mutex_wait_count = {}
    
    mutex_key = f"mutex_{mutex_ptr:x}"
    if mutex_key not in emu._mutex_wait_count:
        emu._mutex_wait_count[mutex_key] = 0
    
    # 2. 增加等待计数
    emu._mutex_wait_count[mutex_key] += 1
    
    # 只在第一次调用时记录详细信息
    if emu._mutex_wait_count[mutex_key] == 1:
        emu.logger.info(f"psynch_mutexwait: mutex=0x{mutex_ptr:x}, timeout={timeout}, flags={flags}")
    
    # 3. 设置最大重试次数，防止无限循环
    MAX_RETRY_COUNT = 3
    
    if emu._mutex_wait_count[mutex_key] > MAX_RETRY_COUNT:
        emu.logger.error(f"psynch_mutexwait: Maximum retry count ({MAX_RETRY_COUNT}) exceeded for mutex 0x{mutex_ptr:x}, stopping emulator to prevent infinite loop")
        emu.log_backtrace()
        # 停止模拟器执行
        emu.uc.emu_stop()
        return -1
    
    # 4. 模拟短暂的等待，然后返回成功
    # 在真实系统中，这里会阻塞直到mutex可用
    # 在模拟环境中，我们假设mutex立即可用
    
    # 只在第一次调用或重试时记录日志，避免无限打印
    if emu._mutex_wait_count[mutex_key] == 1:
        emu.logger.info(f"psynch_mutexwait: Mutex wait completed (simulated, first attempt)")
    elif emu._mutex_wait_count[mutex_key] > 1:
        emu.logger.info(f"psynch_mutexwait: Mutex wait completed (simulated, retry attempt {emu._mutex_wait_count[mutex_key]})")
    
    # 5. 重置计数器，表示成功获取了mutex
    emu._mutex_wait_count[mutex_key] = 0
    
    return 0

@register_syscall_handler(const.SYS_PSYNCH_CVWAIT)
def handle_sys_psynch_cvwait(emu: Chomper):
    emu.log_backtrace()
    return 0

@register_syscall_handler(const.SYS_ISSETUGID)
def handle_sys_issetugid(emu: Chomper):
    return 0

@register_syscall_handler(const.SYS_PTHREAD_SIGMASK)
def handle_sys_pthread_sigmask(emu: Chomper):
    """
    Handle SYS_PTHREAD_SIGMASK system call.
    
    This system call examines or changes the signal mask of the calling thread.
    
    Args:
        emu: The Chomper emulator instance
        
    Returns:
        int: 0 on success, -1 on error
    """
    # Get system call arguments
    # x0: how - specifies how the signal mask is changed
    # x1: set - pointer to signal set to be used for modification
    # x2: oset - pointer to signal set to store the old signal mask
    
    how = emu.get_arg(0)
    set_ptr = emu.get_arg(1)
    oset_ptr = emu.get_arg(2)
    
    emu.logger.info(f"pthread_sigmask: how=0x{how:x}, set=0x{set_ptr:x}, oset=0x{oset_ptr:x}")
    
    # Define signal mask operation constants
    SIG_BLOCK = 0      # Add signals to the signal mask
    SIG_UNBLOCK = 1    # Remove signals from the signal mask  
    SIG_SETMASK = 2    # Replace the signal mask
    
    # Validate the 'how' parameter
    if how not in [SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK]:
        # Map invalid values to closest valid ones for compatibility
        if how == 3:
            # Value 3 might be a typo or extension, map to SIG_SETMASK
            emu.logger.warning(f"Invalid pthread_sigmask 'how' parameter: {how}, mapping to SIG_SETMASK")
            how = SIG_SETMASK
        else:
            emu.logger.error(f"Invalid pthread_sigmask 'how' parameter: {how}")
            return -1
    
    # If oset is not NULL, save the current signal mask
    if oset_ptr != 0:
        # For simplicity, we'll set the old signal mask to 0 (no signals blocked)
        # In a real implementation, this would track the actual signal mask
        emu.write_u64(oset_ptr, 0)  # Write 64-bit signal mask
        emu.logger.info("Saved old signal mask to oset")
    
    # Process the new signal mask if set is not NULL
    if set_ptr != 0:
        new_mask = emu.read_u64(set_ptr)
        emu.logger.info(f"New signal mask: 0x{new_mask:x}")
        
        # In a real implementation, we would:
        # 1. Apply the signal mask based on the 'how' parameter
        # 2. Update the thread's signal mask state
        # 3. Handle signal delivery accordingly
        
        if how == SIG_BLOCK:
            emu.logger.info("SIG_BLOCK: Adding signals to mask")
        elif how == SIG_UNBLOCK:
            emu.logger.info("SIG_UNBLOCK: Removing signals from mask")
        elif how == SIG_SETMASK:
            emu.logger.info("SIG_SETMASK: Replacing signal mask")
    
    # pthread_sigmask returns 0 on success, -1 on error
    return 0

@register_syscall_handler(const.SYS_PROC_INFO)
def handle_sys_proc_info(emu: Chomper):
    pid = emu.get_arg(1)
    flavor = emu.get_arg(2)
    buffer = emu.get_arg(4)

    if pid != emu.ios_os.pid:
        permission_denied()

    if flavor == 3:
        emu.write_string(buffer, emu.ios_os.program_path.split("/")[-1])
    elif flavor == 11:
        emu.write_string(buffer, emu.ios_os.program_path)

    return 0


@register_syscall_handler(const.SYS_STAT64)
def handle_sys_stat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.stat(path))

    return 0


@register_syscall_handler(const.SYS_FSTAT64)
def handle_sys_fstat64(emu: Chomper):
    fd = emu.get_arg(0)
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.fstat(fd))

    return 0


@register_syscall_handler(const.SYS_LSTAT64)
def handle_sys_lstat64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    stat = emu.get_arg(1)

    emu.write_bytes(stat, emu.os.lstat(path))

    return 0


@register_syscall_handler(const.SYS_GETDIRENTRIES64)
def handle_sys_getdirentries64(emu: Chomper):
    fd = emu.get_arg(0)
    buf = emu.get_arg(1)
    nbytes = emu.get_arg(2)
    basep = emu.get_arg(3)

    base = emu.read_u64(basep)

    result = emu.ios_os.getdirentries(fd, base)
    if result is None:
        return 0

    if nbytes < len(result):
        return 0

    emu.write_bytes(buf, result[:nbytes])
    emu.write_u64(basep, base + 1)

    return len(result)


@register_syscall_handler(const.SYS_STATFS64)
def handle_sys_statfs64(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.statfs(path))

    return 0


@register_syscall_handler(const.SYS_FSTATFS64)
def handle_sys_fstatfs64(emu: Chomper):
    fd = emu.get_arg(0)
    statfs = emu.get_arg(1)

    emu.write_bytes(statfs, emu.os.fstatfs(fd))

    return 0


@register_syscall_handler(const.SYS_FSSTAT64)
def handle_sys_fsstat64(emu: Chomper):
    statfs = emu.get_arg(0)
    if not statfs:
        return 1

    emu.write_bytes(statfs, emu.os.statfs("/"))

    return 0


@register_syscall_handler(const.SYS_BSDTHREAD_CREATE)
def handle_sys_bsdthread_create(emu: Chomper):
    """
    Handle SYS_BSDTHREAD_CREATE system call.
    
    This system call creates a new BSD thread with the specified function and parameters.
    
    Args:
        emu: The Chomper emulator instance
        
    Returns:
        int: Thread ID on success, -1 on failure
    """
    # Get system call arguments
    # x0: user_func - function to execute in the new thread (start_routine)
    # x1: user_arg - argument to pass to the thread function (arg)
    # x2: stack - stack address for the new thread
    # x3: threadptr - pointer to pthread_t structure
    # x4: flags - thread creation flags
    
    user_func = emu.get_arg(0)
    user_arg = emu.get_arg(1)
    stack = emu.get_arg(2)
    threadptr = emu.get_arg(3)
    flags = emu.get_arg(4)
    
    emu.logger.info(f"Creating BSD thread: func=0x{user_func:x}, arg=0x{user_arg:x}, stack=0x{stack:x}, threadptr=0x{threadptr:x}, flags=0x{flags:x}")
    
    try:
        emu.logger.info("=== Starting BSD thread creation ===")
        
        # Validate thread function address
        if user_func == 0:
            emu.logger.error("Invalid thread function address: 0x0")
            return -1
            
        # Check thread limit to prevent memory issues
        if len(emu.os._threads) >= 100:  # Limit to 100 threads per process
            emu.logger.warning("Thread limit reached (100), cleaning up old threads")
            _cleanup_completed_threads(emu)
            if len(emu.os._threads) >= 100:
                emu.logger.error("Thread limit still exceeded after cleanup")
                return -1
        
        # Generate a unique thread ID
        thread_id = emu.os.pid * 1000 + len(emu.os._threads) + 1
        emu.logger.info(f"Generated thread ID: {thread_id}")
        
        # Create thread structure
        emu.logger.info("Creating thread structure buffer...")
        thread_struct = emu.create_buffer(256)
        emu.logger.info(f"Thread structure allocated at: 0x{thread_struct:x}")
        
        # Initialize thread structure fields
        emu.logger.info("Initializing thread structure fields...")
        
        # Set thread ID
        emu.logger.info(f"Writing thread ID {thread_id} to offset 0x00")
        emu.write_u64(thread_struct + 0x00, thread_id)
        
        # Set thread function and argument
        emu.logger.info(f"Writing user_func 0x{user_func:x} to offset 0x08")
        emu.write_pointer(thread_struct + 0x08, user_func)
        emu.logger.info(f"Writing user_arg 0x{user_arg:x} to offset 0x10")
        emu.write_pointer(thread_struct + 0x10, user_arg)
        
        # Set stack information
        emu.logger.info("Setting up stack information...")
        stack_allocated = False
        if stack != 0:
            # Validate user-provided stack address
            emu.logger.info(f"Using user-provided stack: 0x{stack:x}")
            if stack < 0x1000 or stack > 0x7FFFFFFFFFFFFFFF:
                emu.logger.warning(f"Invalid stack address: 0x{stack:x}")
                return -1
            emu.logger.info(f"Writing stack address 0x{stack:x} to offset 0x18")
            emu.write_pointer(thread_struct + 0x18, stack)
        else:
            # Allocate default stack if none provided
            emu.logger.info("Allocating default stack...")
            default_stack = emu.create_buffer(0x50000)  # STACK_SIZE = 0x50000
            emu.logger.info(f"Default stack allocated at: 0x{default_stack:x}")
            emu.write_pointer(thread_struct + 0x18, default_stack)
            stack_allocated = True
        
        # Set thread local storage (not provided in bsdthread_create, allocate default)
        emu.logger.info("Setting up TLS...")
        tls_allocated = True
        emu.logger.info("Allocating default TLS...")
        default_tls = emu.create_buffer(0x1000)
        emu.logger.info(f"Default TLS allocated at: 0x{default_tls:x}")
        emu.logger.info(f"Writing thread ID {thread_id} to TLS offset 0x18")
        emu.write_u32(default_tls + 0x18, thread_id)
        emu.logger.info(f"Writing TLS address 0x{default_tls:x} to offset 0x20")
        emu.write_pointer(thread_struct + 0x20, default_tls)
        
        # Set thread state (running)
        emu.logger.info("Setting thread state to running...")
        emu.write_u32(thread_struct + 0x28, 1)  # 1 = running
        
        # Set thread flags
        emu.logger.info(f"Setting thread flags: 0x{flags:x}")
        emu.write_u32(thread_struct + 0x2C, flags)
        
        # Set creation time
        import time
        creation_time = int(time.time())
        emu.logger.info(f"Setting creation time: {creation_time}")
        emu.write_u64(thread_struct + 0x30, creation_time)
        
        # Store thread information in OS
        emu.logger.info("Storing thread information in OS...")
        emu.os._threads[thread_id] = {
            'struct': thread_struct,
            'func': user_func,
            'arg': user_arg,
            'stack': emu.read_pointer(thread_struct + 0x18),
            'tls': emu.read_pointer(thread_struct + 0x20),
            'status': 'created',
            'created_time': creation_time,
            'memory_allocated': True,
            'stack_allocated': stack_allocated,
            'tls_allocated': tls_allocated
        }
        emu.logger.info(f"Thread info stored: {emu.os._threads[thread_id]}")
        
        # Write thread ID to pthread_t structure if provided
        if threadptr != 0:
            emu.logger.info(f"Writing thread ID {thread_id} to pthread_t structure at 0x{threadptr:x}")
            try:
                emu.write_pointer(threadptr, thread_id)
                emu.logger.info("Successfully wrote to pthread_t structure")
            except Exception as e:
                emu.logger.warning(f"Failed to write to pthread_t structure at 0x{threadptr:x}: {e}")
                # Don't fail the entire thread creation if pthread_t write fails
        
        # Start thread execution in a separate context
        emu.logger.info(f"BSD thread {thread_id} created successfully")
        
        # Attempt to start thread execution
        try:
            # Create a new execution context for the thread
            # This simulates actual thread execution
            if user_func != 0:
                # Set up thread context and start execution
                emu.logger.info(f"Starting thread execution at 0x{user_func:x}")
                
                # In a real implementation, you would:
                # 1. Save current CPU context
                # 2. Set up new thread context with its own stack and registers
                # 3. Start execution at user_func with user_arg
                # 4. Restore original context
                
                # For now, we'll simulate by calling the function directly
                # This is a simplified approach - in reality you'd want separate contexts
                try:
                    # Set up thread-specific context
                    thread_context = {
                        'thread_id': thread_id,
                        'stack': emu.read_pointer(thread_struct + 0x18),
                        'tls': emu.read_pointer(thread_struct + 0x20)
                    }
                    
                    # Call the thread function with the thread argument
                    # Note: This is a simplified simulation - real threads would have separate contexts
                    emu.logger.info(f"Calling thread function at 0x{user_func:x} with arg 0x{user_arg:x}")
                    emu.call_address(user_func, user_arg)
                    emu.logger.info(f"Thread {thread_id} function completed")
                    
                    # Update thread status
                    emu.os._threads[thread_id]['status'] = 'completed'
                    
                except Exception as thread_e:
                    emu.logger.warning(f"Thread {thread_id} execution failed: {thread_e}")
                    emu.os._threads[thread_id]['status'] = 'failed'
                    emu.os._threads[thread_id]['error'] = str(thread_e)
                    
        except Exception as exec_e:
            emu.logger.warning(f"Failed to start thread execution: {exec_e}")
            # Thread creation succeeded but execution failed - this is acceptable
        
        # Clean up completed threads to prevent memory accumulation
        _cleanup_completed_threads(emu)
        
        return 0
        
    except Exception as e:
        emu.logger.error(f"Failed to create BSD thread: {e}")
        emu.logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        emu.logger.error(f"Exception traceback: {traceback.format_exc()}")
        return -1


def _cleanup_completed_threads(emu: Chomper):
    """Clean up completed threads to free memory."""
    try:
        current_time = int(time.time())
        threads_to_remove = []
        
        for thread_id, thread_info in emu.os._threads.items():
            # Remove threads that have been completed for more than 60 seconds
            if (thread_info.get('status') in ['completed', 'failed'] and 
                current_time - thread_info.get('created_time', 0) > 60):
                
                # Free allocated memory
                if thread_info.get('memory_allocated'):
                    try:
                        if 'struct' in thread_info:
                            emu.free(thread_info['struct'])
                        if 'stack' in thread_info and thread_info['stack'] != 0:
                            # Only free if it's our allocated stack (not user-provided)
                            if thread_info.get('stack_allocated', False):
                                emu.free(thread_info['stack'])
                        if 'tls' in thread_info and thread_info['tls'] != 0:
                            # Only free if it's our allocated TLS (not user-provided)
                            if thread_info.get('tls_allocated', False):
                                emu.free(thread_info['tls'])
                    except Exception as cleanup_e:
                        emu.logger.warning(f"Failed to cleanup thread {thread_id} memory: {cleanup_e}")
                
                threads_to_remove.append(thread_id)
        
        # Remove cleaned up threads
        for thread_id in threads_to_remove:
            del emu.os._threads[thread_id]
            emu.logger.debug(f"Cleaned up thread {thread_id}")
        
        emu.logger.info(f"thread cleaned up completed")
    except Exception as e:
        emu.logger.warning(f"Thread cleanup failed: {e}")


@register_syscall_handler(const.SYS_LCHOWN)
def handle_sys_lchown(emu: Chomper):
    path = emu.read_string(emu.get_arg(0))
    uid = emu.get_arg(1)
    gid = emu.get_arg(2)

    emu.os.lchown(path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_MAC_SYSCALL)
def handle_sys_mac_syscall(emu: Chomper):
    cmd = emu.read_string(emu.get_arg(0))
    emu.logger.info(f"Recv mac syscall command: {cmd}")

    if cmd == "Sandbox":
        pass
    else:
        emu.logger.warning(f"Unhandled mac syscall command: {cmd}")

    return 0


@register_syscall_handler(const.SYS_GETENTROPY)
def handle_sys_getentropy(emu: Chomper):
    buffer = emu.get_arg(0)
    size = emu.get_arg(1)

    rand_bytes = bytes([random.randint(0, 255) for _ in range(size)])
    emu.write_bytes(buffer, rand_bytes)

    return 0


@register_syscall_handler(const.SYS_GETATTRLISTBULK)
def handle_sys_getattrlistbulk(emu: Chomper):
    return 0


@register_syscall_handler(const.SYS_OPENAT)
@register_syscall_handler(const.SYS_OPENAT_NOCANCEL)
def handle_sys_openat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    flags = emu.get_arg(2)
    mode = emu.get_arg(3)

    return emu.os.openat(dir_fd, path, flags, mode)


@register_syscall_handler(const.SYS_FACCESSAT)
def handle_sys_faccessat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    if not emu.os.faccessat(dir_fd, path, mode):
        return -1

    return 0


@register_syscall_handler(const.SYS_FCHMODAT)
def handle_sys_fchmodat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.fchmodat(dir_fd, path, mode)

    return 0


@register_syscall_handler(const.SYS_FCHOWNAT)
def handle_sys_fchownat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    uid = emu.get_arg(2)
    gid = emu.get_arg(3)

    emu.os.fchownat(dir_fd, path, uid, gid)

    return 0


@register_syscall_handler(const.SYS_FSTATAT64)
def handle_sys_fstatat64(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    stat = emu.get_arg(2)

    emu.write_bytes(stat, emu.os.fstatat(dir_fd, path))

    return 0


@register_syscall_handler(const.SYS_RENAMEAT)
def handle_sys_renameat(emu: Chomper):
    src_fd = emu.get_arg(0)
    old = emu.read_string(emu.get_arg(1))
    dst_fd = emu.get_arg(2)
    new = emu.read_string(emu.get_arg(3))

    emu.os.renameat(src_fd, old, dst_fd, new)

    return 0


@register_syscall_handler(const.SYS_LINKAT)
def handle_sys_linkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.linkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_UNLINKAT)
def handle_sys_unlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.unlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_READLINKAT)
def handle_sys_readlinkat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))

    emu.os.readlinkat(dir_fd, path)

    return 0


@register_syscall_handler(const.SYS_SYMLINKAT)
def handle_sys_symlinkat(emu: Chomper):
    src_dir_fd = to_signed(emu.get_arg(0), 4)
    src_path = emu.read_string(emu.get_arg(1))
    dst_dir_fd = to_signed(emu.get_arg(2), 4)
    dst_path = emu.read_string(emu.get_arg(3))

    emu.os.symlinkat(src_dir_fd, src_path, dst_dir_fd, dst_path)

    return 0


@register_syscall_handler(const.SYS_MKDIRAT)
def handle_sys_mkdirat(emu: Chomper):
    dir_fd = to_signed(emu.get_arg(0), 4)
    path = emu.read_string(emu.get_arg(1))
    mode = emu.get_arg(2)

    emu.os.mkdirat(dir_fd, path, mode)

    return 0

@register_syscall_handler(const.SYS_BSDTHREAD_CTL)
def handle_sys_bsdthread_ctl(emu: Chomper):
    """
    Handle SYS_BSDTHREAD_CTL system call.
    
    This system call provides thread control operations for BSD threads.
    
    Args:
        emu: The Chomper emulator instance
        
    Returns:
        int: 0 on success, error code on failure
    """
    # Get system call arguments
    # x0: cmd - command to execute
    # x1: arg1 - first argument
    # x2: arg2 - second argument  
    # x3: arg3 - third argument
    
    cmd = emu.get_arg(0)
    arg1 = emu.get_arg(1)
    arg2 = emu.get_arg(2)
    arg3 = emu.get_arg(3)
    
    emu.logger.info(f"BSD thread control: cmd=0x{cmd:x}, arg1=0x{arg1:x}, arg2=0x{arg2:x}, arg3=0x{arg3:x}")
    
    # Handle different BSD thread control commands
    if cmd == 0x01:  # BSDTHREAD_CTL_SET
        # Set thread attributes
        emu.logger.info("BSDTHREAD_CTL_SET command")
        return 0
        
    elif cmd == 0x02:  # BSDTHREAD_CTL_GET
        # Get thread attributes
        emu.logger.info("BSDTHREAD_CTL_GET command")
        return 0
        
    elif cmd == 0x03:  # BSDTHREAD_CTL_TERMINATE
        # Terminate thread
        emu.logger.info("BSDTHREAD_CTL_TERMINATE command")
        return 0
        
    elif cmd == 0x04:  # BSDTHREAD_CTL_SUSPEND
        # Suspend thread
        emu.logger.info("BSDTHREAD_CTL_SUSPEND command")
        return 0
        
    elif cmd == 0x05:  # BSDTHREAD_CTL_RESUME
        # Resume thread
        emu.logger.info("BSDTHREAD_CTL_RESUME command")
        return 0
        
    else:
        # Unknown command
        emu.logger.warning(f"Unknown BSDTHREAD_CTL command: 0x{cmd:x}")
        return 0  # Return success for unknown commands to avoid crashes

@register_syscall_handler(const.SYS_ULOCK_WAIT)
def handle_sys_ulock_wait(emu: Chomper):
    return 0

@register_syscall_handler(const.SYS_ULOCK_WAKE)
def handle_sys_ulock_wake(emu: Chomper):
    return 0

@register_syscall_handler(const.SYS_TERMINATE_WITH_PAYLOAD)
def handle_sys_terminate_with_payload(emu: Chomper):
    return 0

@register_syscall_handler(const.SYS_ABORT_WITH_PAYLOAD)
def handle_sys_abort_with_payload(emu: Chomper):
    return 0

@register_syscall_handler(const.SYS_PREADV)
@register_syscall_handler(const.SYS_PREADV_NOCANCEL)
def handle_sys_preadv(emu: Chomper):
    fd = emu.get_arg(0)
    iov = emu.get_arg(1)
    iovcnt = emu.get_arg(2)
    offset = emu.get_arg(3)

    pos = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, offset, os.SEEK_SET)

    result = 0

    for _ in range(iovcnt):
        iov_base = emu.read_pointer(iov)
        iov_len = emu.read_u64(iov + 8)

        data = emu.os.read(fd, iov_len)
        emu.write_bytes(iov_base, data)

        result += len(data)

        if len(data) != iov_len:
            break

        iov += 16

    os.lseek(fd, pos, os.SEEK_SET)

    return result


@register_syscall_handler(const.MACH_ABSOLUTE_TIME_TRAP)
def handle_mach_absolute_time_trap(emu: Chomper):
    return int(time.time_ns() % (3600 * 10**9))


@register_syscall_handler(const.KERNELRPC_MACH_VM_ALLOCATE_TRAP)
def handle_kernelrpc_mach_vm_allocate_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_DEALLOCATE_TRAP)
def handle_kernelrpc_mach_vm_deallocate_trap(emu: Chomper):
    mem = emu.get_arg(1)

    emu.memory_manager.free(mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_PROTECT_TRAP)
def handle_kernelrpc_mach_vm_protect_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_VM_MAP_TRAP)
def handle_kernelrpc_mach_vm_map_trap(emu: Chomper):
    address = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(size)
    emu.write_pointer(address, mem)

    return 0


@register_syscall_handler(const.KERNELRPC_MACH_PORT_ALLOCATE_TRAP)
def handle_kernelrpc_mach_port_allocate_trap(emu: Chomper):
    return 0

@register_syscall_handler(const.KERNELRPC_MACH_PORT_DEALLOCATE_TRAP)
def handle_kernelrpc_mach_port_deallocate_trap(emu: Chomper):
    return 0

@register_syscall_handler(const.KERNELRPC_MACH_PORT_INSERT_MEMBER_TRAP)
def handle_kernelrpc_mach_port_insert_member_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.KERNELRPC_MACH_PORT_CONSTRUCT_TRAP)
def handle_kernelrpc_mach_port_construct_trap(emu: Chomper):
    name = emu.get_arg(3)

    # mach_port_name
    emu.write_u32(name, 1)

    return 0


@register_syscall_handler(const.MACH_REPLY_PORT_TRAP)
def handle_mach_reply_port_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.TASK_SELF_TRAP)
def handle_task_self_trap(emu: Chomper):
    return 0


@register_syscall_handler(const.HOST_SELF_TRAP)
def handle_host_self_trap(emu: Chomper):
    return 2563


@register_syscall_handler(const.MACH_MSG_TRAP)
def handle_mach_msg_trap(emu: Chomper):
    msg_ptr = emu.get_arg(0)
    msg_raw = emu.read_bytes(msg_ptr, ctypes.sizeof(MachMsgHeaderT))
    msg = bytes_to_struct(msg_raw, MachMsgHeaderT)

    msg_id = msg.msgh_id
    remote_port = msg.msgh_remote_port

    option = emu.get_arg(1)

    emu.logger.info(
        "Recv mach msg: msg_id=%s, remote_port=%s, option=0x%x",
        msg_id,
        remote_port,
        option,
    )

    if remote_port == emu.ios_os.MACH_PORT_HOST_SELF:
        if msg_id == 412:  # host_get_special_port
            return 6
    elif remote_port == emu.ios_os.MACH_PORT_TASK_SELF:
        if msg_id == 3418:  # semaphore_create
            if option & const.MACH_RCV_MSG:
                # policy = emu.read_s32(msg_ptr + 0x20)
                value = emu.read_s32(msg_ptr + 0x24)

                semaphore = emu.ios_os.semaphore_create(value)

                msg.msgh_bits |= const.MACH_MSGH_BITS_COMPLEX
                msg.msgh_size = 40
                msg.msgh_remote_port = 0
                msg.msgh_id = 3518

                ndr = NDRRecordT(
                    mig_vers=1,
                )

                replay = ReplayFmtT(
                    hdr=msg,
                    ndr=ndr,
                    kr=semaphore,
                )

                padding = b"\x00" * 6 + b"\x11"
                emu.write_bytes(msg_ptr, struct_to_bytes(replay) + padding)
            return 0
        elif msg_id == 8000:  # task_restartable_ranges_register
            return 6
    elif remote_port == emu.ios_os.MACH_PORT_NOTIFICATION_CENTER:
        return 0

    return 6

@register_syscall_handler(const.SWTCH_PRI)
def handle_swtch_pri(emu: Chomper):
    return True


@register_syscall_handler(const.KERNELRPC_MACH_PORT_TYPE_TRAP)
def handle_kernelrpc_mach_port_type_trap(emu: Chomper):
    ptype = emu.get_arg(2)

    value = 0
    value |= const.MACH_PORT_TYPE_SEND
    value |= const.MACH_PORT_TYPE_RECEIVE

    emu.write_u32(ptype, value)

    return 0


@register_syscall_handler(const.MACH_TIMEBASE_INFO_TRAP)
def handle_mach_timebase_info_trap(emu: Chomper):
    info = emu.get_arg(0)

    emu.write_u32(info, 1)
    emu.write_u32(info + 4, 1)

    return 0


@register_syscall_handler(const.MK_TIMER_CREATE_TRAP)
def handle_mk_timer_create_trap(emu: Chomper):
    # Return mach_port_name
    return 1
