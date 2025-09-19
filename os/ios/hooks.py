import os
from functools import wraps
from typing import Callable, Dict, Optional

from unicorn import Uc, UcError

from chomper.exceptions import EmulatorCrashed, SymbolMissing, ObjCUnrecognizedSelector
from chomper.objc import ObjC, pyobj2cfobj
from chomper.typing import HookContext

hooks: Dict[str, Callable] = {}


def get_hooks() -> Dict[str, Callable]:
    """Returns a dictionary of default hooks."""
    return hooks.copy()


def register_hook(symbol_name: str):
    """Decorator to register a hook function for a given symbol name."""

    def wrapper(f):
        @wraps(f)
        def decorator(
            uc: Uc, address: int, size: int, user_data: HookContext
        ) -> Optional[int]:
            return f(uc, address, size, user_data)

        hooks[symbol_name] = decorator
        return f

    return wrapper


@register_hook("_pthread_self")
def hook_pthread_self(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    return emu.read_pointer(emu.find_symbol("__main_thread_ptr").address)

@register_hook("_pthread_join")
def hook_pthread_join(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    print(f"_pthread_join called x0 {emu.get_arg(0)}")

    return 0


@register_hook("_malloc")
def hook_malloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(0)
    mem = emu.memory_manager.alloc(size)

    return mem


@register_hook("_calloc")
def hook_calloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    numitems = emu.get_arg(0)
    size = emu.get_arg(1)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_realloc")
def hook_realloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    ptr = emu.get_arg(0)
    size = emu.get_arg(1)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_free")
def hook_free(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(0)
    emu.memory_manager.free(mem)


@register_hook("_malloc_size")
def hook_malloc_size(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(0)

    for pool in emu.memory_manager.pools:
        if pool.address <= mem < pool.address + pool.size:
            return pool.block_size

    return 0


@register_hook("_malloc_default_zone")
def hook_malloc_default_zone(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_zone_malloc")
def hook_malloc_zone_malloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    
    size = emu.get_arg(1)
    mem = emu.memory_manager.alloc(size)
    return mem


@register_hook("_malloc_zone_calloc")
def hook_malloc_zone_calloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    numitems = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.alloc(numitems * size)
    emu.write_bytes(mem, b"\x00" * (numitems * size))

    return mem


@register_hook("_malloc_zone_realloc")
def hook_malloc_zone_realloc(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    ptr = emu.get_arg(1)
    size = emu.get_arg(2)

    return emu.memory_manager.realloc(ptr, size)


@register_hook("_malloc_zone_free")
def hook_malloc_zone_free(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    mem = emu.get_arg(1)
    emu.memory_manager.free(mem)


@register_hook("_malloc_zone_from_ptr")
def hook_malloc_zone_from_ptr(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_malloc_zone_memalign")
def hook_malloc_zone_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    print(f"hook_malloc_zone_memalign x0 {emu.get_arg(0)} x1 {emu.get_arg(1)} x2 {emu.get_arg(2)}")

    alignment = emu.get_arg(1)
    size = emu.get_arg(2)
    mem = emu.memory_manager.memalign(alignment, size)

    return mem


@register_hook("_malloc_good_size")
def hook_malloc_good_size(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    size = emu.get_arg(0)

    return size


@register_hook("_malloc_engaged_nano")
def hook_malloc_engaged_nano(uc: Uc, address: int, size: int, user_data: HookContext):
    return 1


@register_hook("_posix_memalign")
def hook_posix_memalign(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    memptr = emu.get_arg(0)
    alignment = emu.get_arg(1)
    size = emu.get_arg(2)

    mem = emu.memory_manager.memalign(alignment, size)
    emu.write_pointer(memptr, mem)

    return 0


@register_hook("__os_activity_initiate")
def hook_os_activity_initiate(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_notify_register_dispatch")
def hook_notify_register_dispatch(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_notify_register_check")
def hook_notify_register_check(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_dlopen")
def hook_dlopen(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    if not emu.get_arg(0):
        return emu.modules[-1].base

    path = emu.read_string(emu.get_arg(0))
    module_name = path.split("/")[-1]

    # Check module loading status
    for module in emu.modules:
        if path.endswith(module.name):
            return module.base

    # For system modules, attempt to load
    try:
        emu.os.search_module_binary(module_name)  # type: ignore
        emu.os.resolve_modules([module_name])  # type: ignore

        found_module = emu.find_module(module_name)
        if found_module:
            return found_module.base
    except FileNotFoundError:
        pass

    raise EmulatorCrashed(f"doesn't support dlopen: '{path}'")


@register_hook("_dlsym")
def hook_dlsym(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    symbol_name = f"_{emu.read_string(emu.get_arg(1))}"

    try:
        symbol = emu.find_symbol(symbol_name)
        return symbol.address
    except SymbolMissing:
        pass

    return 0


@register_hook("_dyld_program_sdk_at_least")
def hook_dyld_program_sdk_at_least(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0

@register_hook("_dispatch_once")
def hook_dispatch_once(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    
    # dispatch_once(predicate, block) 的参数
    predicate = emu.get_arg(0)  # dispatch_once_t *predicate
    block = emu.get_arg(1)       # dispatch_block_t block
    
    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.info(f"dispatch_once called from {from_}: predicate=0x{predicate:x}, block=0x{block:x}")
    emu.log_backtrace()

    try:
        if predicate != 0 and block != 0:
            # 检查predicate的当前值
            predicate_value_bytes = emu.uc.mem_read(predicate, 8)
            predicate_value = int.from_bytes(predicate_value_bytes, byteorder='little')
            
            # 如果predicate为0，表示代码块尚未执行
            if predicate_value == 0:
                emu.logger.info(f"dispatch_once: executing block for first time")
                
                # 读取block的实际函数地址（block结构体中的invoke字段）
                block_invoke_bytes = emu.uc.mem_read(block + 8*2, 8)
                block_invoke_addr = int.from_bytes(block_invoke_bytes, byteorder='little')
                
                if block_invoke_addr != 0:
                    # 执行block
                    emu.logger.info(f"dispatch_once: executing block at 0x{block_invoke_addr:x}")
                    emu.call_address(block_invoke_addr, block)
                    
                    # 将predicate设置为已执行状态（~0L）
                    executed_value = ~0 & 0xFFFFFFFFFFFFFFFF  # 64位全1
                    emu.uc.mem_write(predicate, executed_value.to_bytes(8, byteorder='little'))
                    emu.logger.info(f"dispatch_once: block executed, predicate set to 0x{executed_value:x}")
                else:
                    emu.logger.warning(f"dispatch_once: block invoke address is null")
            else:
                emu.logger.info(f"dispatch_once: block already executed (predicate=0x{predicate_value:x}), skipping")
        else:
            emu.logger.warning(f"dispatch_once: invalid parameters - predicate=0x{predicate:x}, block=0x{block:x}")
            
    except Exception as e:
        emu.logger.warning(f"Error in dispatch_once hook: {e}")
    
    return 0

@register_hook("_dispatch_async")
def hook_dispatch_async(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    
    # dispatch_async(queue, block) 的参数
    queue = emu.get_arg(0)  # dispatch_queue_t queue
    block = emu.get_arg(1)  # dispatch_block_t block
    
    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.info(f"dispatch_async called from {from_}: queue=0x{queue:x}, block=0x{block:x}")
    emu.log_backtrace()
    # if emu.uc.reg_read(emu.arch.reg_lr) == 0x1800b5fe8:
    #     emu.logger.info(f"dispatch_async called from 0x1800b5fe8, return")
    #     return 0x10086
    
    # 在模拟环境中，我们可以选择：
    # 1. 忽略异步调用（当前实现）
    # 2. 立即同步执行block
    # 3. 模拟异步执行
    
    # 选项1：忽略异步调用（推荐用于大多数情况）
    # emu.logger.warning(f"Emulator ignored a 'dispatch_async' call from {from_}.")
    
    # 选项2：立即同步执行block（谨慎使用，可能导致死锁）
    
    try:
        if block != 0:
            # 读取block的实际函数地址（block结构体中的invoke字段）
            block_invoke_bytes = emu.uc.mem_read(block + 8*2, 8)
            block_invoke_addr = int.from_bytes(block_invoke_bytes, byteorder='little')
            
            # 读取block的参数
            # param1_bytes = emu.uc.mem_read(block + 8*4, 8)
            # param1 = int.from_bytes(param1_bytes, byteorder='little')
            
            # param2_bytes = emu.uc.mem_read(block + 8*5, 8)
            # param2 = int.from_bytes(param2_bytes, byteorder='little')
            
            emu.logger.info(f"Executing block synchronously at 0x{block_invoke_addr:x}")
            # emu.logger.info(f"Block parameters: param1=0x{param1:x}, param2=0x{param2:x}")
            
            # 保存当前上下文
            context = emu.uc.context_save()
            try:
                # 调用block的实际函数，传入参数
                emu.call_address(block_invoke_addr, block, 0x50000, 0x403)
            except Exception as e:
                emu.logger.warning(f"Failed to execute block: {e}")
            finally:
                emu.uc.context_restore(context)
                emu.logger.info(f"block_invoke_addr:0x{block_invoke_addr:x} execute success")
    except Exception as e:
        emu.logger.warning(f"Error in dispatch_async hook: {e}")

    return 0

# @register_hook("__dispatch_client_callout")
# def hook_dispatch_client_callout(uc: Uc, address: int, size: int, user_data: HookContext):
#     emu = user_data["emu"]
    
#     # __dispatch_client_callout(function, context) 的参数
#     function = emu.get_arg(0)  # 要执行的函数指针
#     context = emu.get_arg(1)   # 传递给函数的上下文参数
    
#     from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
#     emu.logger.info(f"__dispatch_client_callout called from {from_}: function=0x{function:x}, context=0x{context:x}")
    
    # try:
    #     if function != 0:
    #         # 保存当前上下文
    #         context_save = emu.uc.context_save()
    #         try:
    #             # 调用用户提交的函数，传入context参数
    #             emu.logger.info(f"Executing user function at 0x{function:x} with context 0x{context:x}")
    #             result = emu.call_address(function, context)
    #             emu.logger.info(f"User function execution completed, result: 0x{result:x}")
    #             return result
    #         except Exception as e:
    #             emu.logger.warning(f"Failed to execute user function: {e}")
    #             return 0
    #         finally:
    #             emu.uc.context_restore(context_save)
    #     else:
    #         emu.logger.warning("__dispatch_client_callout called with null function pointer")
    #         return 0
    # except Exception as e:
    #     emu.logger.warning(f"Error in __dispatch_client_callout hook: {e}")
    #     return 0

@register_hook("_dispatch_resume")
def hook_dispatch_resume(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0

@register_hook("__dyld_image_count")
def hook_dyld_image_count(uc: Uc, address: int, size: int, user_data: HookContext):
    """
    Hook for _dyld_image_count function.
    
    Returns the number of loaded images (modules) in the dyld image list.
    This uses the ALL_MODULES defined in os.py.
    
    Args:
        uc: Unicorn engine instance
        address: Address where the hook was triggered
        size: Size of the instruction
        user_data: Hook context containing emulator instance
        
    Returns:
        int: Number of loaded images
    """
    emu = user_data["emu"]
    
    # 导入 os.py 中定义的 ALL_MODULES
    from .os import ALL_MODULES
    
    # 计算总模块数
    total_count = len(emu.os._dyld_image_info)
    
    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.info(f"dyld_image_count called from {from_}: returning {total_count} images")
    
    return total_count

@register_hook("__dyld_get_image_header")
def hook_dyld_get_image_header(uc: Uc, address: int, size: int, user_data: HookContext):
    """
    Hook for _dyld_get_image_header function.
    
    Returns a pointer to the mach_header structure for the specified image.
    This function is used to get information about loaded images.
    
    Args:
        uc: Unicorn engine instance
        address: Address where the hook was triggered
        size: Size of the instruction
        user_data: Hook context containing emulator instance
        
    Returns:
        int: Pointer to mach_header structure, or 0 if image not found
    """
    emu = user_data["emu"]
    
    # 获取参数：image_index (整数索引)
    image_index = emu.get_arg(0)
    
    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.info(f"dyld_get_image_header called from {from_}: image_index={image_index}")
    
    # 检查是否有 dyld 信息字典
    if not hasattr(emu.os, '_dyld_image_info'):
        emu.logger.warning("dyld_get_image_header: _dyld_image_info not found")
        return 0
    
    # 检查索引是否有效
    if image_index not in emu.os._dyld_image_info:
        emu.logger.warning(f"dyld_get_image_header: invalid image_index {image_index}")
        return 0
    
    # 获取图像信息
    image_info = emu.os._dyld_image_info[image_index]
    dli_fbase = image_info['dli_fbase']  # 模块基地址
    
    emu.logger.info(f"dyld_get_image_header: returning mach_header for {image_info['module_name']} at 0x{dli_fbase:x}")
    
    # 返回 mach_header 结构体的地址（即模块基地址）
    return dli_fbase

@register_hook("_dyld_get_image_vmaddr_slide")
def hook_dyld_get_image_vmaddr_slide(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0

@register_hook("_dispatch_group_async")
def hook_dispatch_group_async(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0

@register_hook("_dispatch_activate")
def hook_dispatch_activate(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_dispatch_barrier_async")
def hook_dispatch_barrier_async(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.warning(
        f"Emulator ignored a 'dispatch_barrier_async' call from {from_}."
    )

    return 0

@register_hook("_pthread_create")
def hook_pthread_create(uc: Uc, address: int, size: int, user_data: HookContext):
    """
    Hook for pthread_create function.
    
    Creates a new thread with the specified attributes and start routine.
    In the emulator, we simulate thread creation but don't actually create new threads.
    
    Args:
        uc: Unicorn engine instance
        address: Address where the hook was triggered
        size: Size of the instruction
        user_data: Hook context containing emulator instance
        
    Returns:
        int: 0 on success, error code on failure
    """
    emu = user_data["emu"]
    
    # pthread_create 的参数
    # x0: pthread_t *thread - 指向新线程ID的指针
    # x1: const pthread_attr_t *attr - 线程属性
    # x2: void *(*start_routine)(void *) - 线程入口函数
    # x3: void *arg - 传递给线程函数的参数
    
    thread_ptr = emu.get_arg(0)  # pthread_t *thread
    attr_ptr = emu.get_arg(1)    # pthread_attr_t *attr
    start_routine = emu.get_arg(2)  # 线程入口函数
    arg = emu.get_arg(3)         # 传递给线程的参数
    
    from_ = emu.debug_symbol(emu.uc.reg_read(emu.arch.reg_lr))
    emu.logger.info(f"pthread_create called from {from_}: thread_ptr=0x{thread_ptr:x}, attr=0x{attr_ptr:x}, start_routine=0x{start_routine:x}, arg=0x{arg:x}")
    
    try:
        # 初始化线程跟踪字典
        if not hasattr(emu, '_thread_info'):
            emu._thread_info = {}
            emu._next_thread_id = 1
        
        # 生成一个模拟的线程ID
        thread_id = emu._next_thread_id
        emu._next_thread_id += 1
        
        # 将线程ID写入指定的内存位置
        if thread_ptr != 0:
            emu.uc.mem_write(thread_ptr, thread_id.to_bytes(8, byteorder='little'))
        
        # 记录线程信息
        emu._thread_info[thread_id] = {
            'start_routine': start_routine,
            'arg': arg,
            'attr': attr_ptr,
            'created_from': from_,
            'status': 'created'
        }
        
        emu.logger.info(f"pthread_create: created thread {thread_id}, start_routine=0x{start_routine:x}")
        
        # 实际执行线程函数
        if start_routine != 0:
            try:
                emu.logger.info(f"pthread_create: executing thread {thread_id} function at 0x{start_routine:x} with arg 0x{arg:x}")
                
                # 保存当前上下文
                current_pc = emu.uc.reg_read(emu.arch.reg_pc)
                current_sp = emu.uc.reg_read(emu.arch.reg_sp)
                
                # 调用线程函数
                # 注意：这里直接调用可能会影响当前执行流程
                # 在实际实现中，可能需要更复杂的线程管理
                result = emu.call_address(start_routine, arg)
                
                emu.logger.info(f"pthread_create: thread {thread_id} function completed with result 0x{result:x}")
                
                # 更新线程状态
                emu._thread_info[thread_id]['status'] = 'completed'
                emu._thread_info[thread_id]['result'] = result
                
            except Exception as e:
                emu.logger.error(f"pthread_create: error executing thread {thread_id} function: {e}")
                emu._thread_info[thread_id]['status'] = 'error'
                emu._thread_info[thread_id]['error'] = str(e)
        else:
            emu.logger.warning(f"pthread_create: thread {thread_id} has null start_routine")
            emu._thread_info[thread_id]['status'] = 'invalid'
        
        emu.logger.info(f"pthread_create: thread {thread_id} creation and execution completed")
        
        return 0  # 成功
        
    except Exception as e:
        emu.logger.error(f"pthread_create: error creating thread: {e}")
        return -1  # 失败

@register_hook("_pthread_detach")
def hook_pthread_detach(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_MGCopyAnswer")
def hook_mg_copy_answer(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    objc = ObjC(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "cStringUsingEncoding:", 4)
    key = emu.read_string(str_ptr)

    if key in emu.ios_os.device_info:
        return pyobj2cfobj(emu, emu.ios_os.device_info[key])

    return 0


@register_hook("__CFPreferencesCopyAppValueWithContainerAndConfiguration")
def hook_cf_preferences_copy_app_value_with_container_and_configuration(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]
    objc = ObjC(emu)

    str_ptr = objc.msg_send(emu.get_arg(0), "cStringUsingEncoding:", 4)
    key = emu.read_string(str_ptr)

    if key in emu.ios_os.preferences:
        return pyobj2cfobj(emu, emu.ios_os.preferences[key])

    return 0


@register_hook("__CFBundleCreateInfoDictFromMainExecutable")
def hook_cf_bundle_create_info_dict_from_main_executable(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    executable_dir = os.path.dirname(emu.ios_os.executable_path)
    info_path = os.path.join(executable_dir, "Info.plist")

    if not os.path.exists(info_path):
        raise FileNotFoundError(
            "File 'Info.plist' not found, please ensure that 'Info.plist' "
            "and executable file are in the same directory."
        )

    with open(info_path, "rb") as f:
        info_content = f.read()

    info_data = emu.create_buffer(len(info_content) + 100)
    emu.write_bytes(info_data, info_content)

    cf_bundle = emu.call_symbol(
        "__CFBundleCreateInfoDictFromData", info_data, len(info_content)
    )

    return cf_bundle


@register_hook("___CFXPreferencesCopyCurrentApplicationStateWithDeadlockAvoidance")
def hook_cf_x_preferences_copy_current_application_state_with_deadlock_avoidance(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    return pyobj2cfobj(emu, emu.ios_os.preferences)


@register_hook("_CFNotificationCenterGetLocalCenter")
def hook_cf_notification_center_get_local_center(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_CFNotificationCenterAddObserver")
def hook_cf_notification_center_add_observer(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_CFNotificationCenterPostNotification")
def hook_cf_notification_center_post_notification(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_SecItemAdd")
def hook_sec_item_add(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemUpdate")
def hook_sec_item_update(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemDelete")
def hook_sec_item_delete(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("_SecItemCopyMatching")
def hook_sec_item_copy_matching(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]
    objc = ObjC(emu)

    a1 = emu.get_arg(0)
    a2 = emu.get_arg(1)

    sec_return_data = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnData").address),
    )

    sec_return_attributes = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecReturnAttributes").address),
    )

    sec_match_limit = objc.msg_send(
        a1,
        "objectForKey:",
        emu.read_pointer(emu.find_symbol("_kSecMatchLimit").address),
    )

    cf_boolean_true = emu.read_pointer(emu.find_symbol("_kCFBooleanTrue").address)

    sec_match_limit_all = emu.read_pointer(
        emu.find_symbol("_kSecMatchLimitAll").address
    )

    if sec_match_limit == sec_match_limit_all:
        result = pyobj2cfobj(emu, [])
    elif sec_return_attributes == cf_boolean_true:
        result = pyobj2cfobj(emu, {})
    elif sec_return_data == cf_boolean_true:
        # result = pyobj2cfobj(emu, b"")
        result = 0
    else:
        result = 0

    if a2:
        emu.write_u64(a2, result)

    return 0


@register_hook("_nw_path_create_evaluator_for_endpoint")
def hook_nw_path_create_evaluator_for_endpoint(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    return 0


@register_hook("_bootstrap_look_up2")
def hook_bootstrap_look_up2(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0


@register_hook("+[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_class(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_name = emu.read_string(emu.call_symbol("_class_getName", receiver))
    print(f"Unrecognized selector '{selector}' of class '{class_name}'")
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of class '{class_name}'"
    )

# @register_hook("+[TBNavigationController load]")
# def hook_TBNavigationController_load(
#     uc: Uc, address: int, size: int, user_data: HookContext
# ):
#     print(f"call +[TBNavigationController load]")
#     return 0

# @register_hook("+[NSDictionary dictionary]")
# def hook_NSDictionary_dictionary(
#     uc: Uc, address: int, size: int, user_data: HookContext
# ):
#     print(f"call +[NSDictionary dictionary]")
#     emu = user_data["emu"]
#     objc = ObjC(emu)

#     receiver = emu.get_arg(0)
#     selector = emu.get_arg(1)
#     return objc.msg_send(receiver,selector)

@register_hook("-[NSObject(NSObject) doesNotRecognizeSelector:]")
def hook_ns_object_does_not_recognize_selector_for_instance(
    uc: Uc, address: int, size: int, user_data: HookContext
):
    emu = user_data["emu"]

    receiver = emu.get_arg(0)
    selector = emu.read_string(emu.get_arg(2))

    class_ = emu.call_symbol("_object_getClass", receiver)
    class_name = emu.read_string(emu.call_symbol("_class_getName", class_))

    emu.log_backtrace()
    raise ObjCUnrecognizedSelector(
        f"Unrecognized selector '{selector}' of instance '{class_name}'"
    )


@register_hook("__ZL9readClassP10objc_classbb")
def hook_read_class(uc: Uc, address: int, size: int, user_data: HookContext):
    emu = user_data["emu"]

    a1 = emu.get_arg(0)
    a2 = emu.get_arg(1)
    a3 = emu.get_arg(2)

    context = emu.uc.context_save()

    class_name = ""

    try:
        data_ptr = emu.read_pointer(a1 + 32)
        if data_ptr:
            name_ptr = emu.read_pointer(data_ptr + 24)
            class_name = emu.read_string(name_ptr)
    except (UnicodeDecodeError, UcError):
        pass

    emu.uc.reg_write(emu.arch.reg_sp, emu.uc.reg_read(emu.arch.reg_sp) - 0x60)

    try:
        read_class_addr = emu.find_symbol("__ZL9readClassP10objc_classbb").address
        result = emu.call_address(read_class_addr + 4, a1, a2, a3)
    except EmulatorCrashed:
        emu.logger.warning(
            "readClass failed: %s",
            f'"{class_name}"' if class_name else emu.debug_symbol(a1),
        )
        result = 0
    finally:
        emu.uc.context_restore(context)

    return result

@register_hook("___cxa_atexit")
def hook_cxa_atexit(uc: Uc, address: int, size: int, user_data: HookContext):
    return 0