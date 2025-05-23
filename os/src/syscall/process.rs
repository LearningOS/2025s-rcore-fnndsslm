//! Process management syscalls
use crate::{config::PAGE_SIZE, mm::{PageTable,VirtAddr,MapArea,MapPermission,MapType}, task::{change_program_brk, exit_current_and_run_next, suspend_current_and_run_next}, timer::get_time_us};
use crate::task;
use crate::task::current_user_token;
use core::mem;
#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let page_table = PageTable::from_token(current_user_token());
    let va = VirtAddr::from(_ts as usize);
    let vpn = va.floor();

    let time_val_size = mem::size_of::<TimeVal>();
    let last_vpn = VirtAddr::from(_ts as usize + time_val_size - 1).floor(); 
    let pte = page_table.translate(vpn).expect("Failed to translate virtual address");
    if !pte.writable() {
        return -1;
    }
    if vpn != last_vpn {
        let pte2 = page_table.translate(last_vpn).expect("Failed to translate virtual address");
        if !pte2.writable() {
            return -1;
        }
    }

    let pte = page_table.translate(vpn).expect("Failed to translate virtual address");
    if !pte.writable(){
        return -1;
    }   
    let time_val = unsafe {
        let base = pte.ppn().get_bytes_array().as_mut_ptr(); 
        let ptr = base.add(va.page_offset()) as *mut TimeVal; 
        &mut *ptr
    };
    let time_us = get_time_us();
    time_val.sec = time_us / 1_000_000;
    time_val.usec = time_us % 1_000_000;

    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");
    match _trace_request{
        0 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id as usize);
            let vpn = va.floor();
            if let Some(pte) = page_table.translate(vpn) {
                if pte.readable() {
                    let base = pte.ppn().get_bytes_array().as_mut_ptr();
                    let ptr = unsafe {
                        base.add(va.page_offset())
                    };
                    unsafe {
                        return *ptr as isize;
                    }
                } else {
                    return -1;
                }
            } else {
                return -1;
            }
        },
        1 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id as usize);
            let vpn = va.floor();
            if let Some(pte) = page_table.translate(vpn) {
                if pte.writable() {
                    let base = pte.ppn().get_bytes_array().as_mut_ptr();
                    let ptr = unsafe {
                        base.add(va.page_offset())
                    };
                    unsafe {
                        *ptr = _data as u8;
                    }
                    0
                } else {
                    -1
                }
            } else {
                -1
            }
        },
        2 => {
            let mut inner = task::TASK_MANAGER.get_inner().exclusive_access(); 
            let current_task = inner.get_task();
            match _id{
                64 => current_task.num_syscall_write as isize,
                93 => current_task.num_syscall_exit as isize,
                124 => current_task.num_syscall_yield as isize,
                169 => current_task.num_syscall_get_time as isize,
                214 => current_task.num_syscall_sbrk as isize,
                215 => current_task.num_syscall_munmap as isize,
                222 => current_task.num_syscall_mmap as isize,
                410 => current_task.num_syscall_trace as isize,
                 _ => -1
            }
        },
        _ => -1
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if _start % PAGE_SIZE != 0 {
        return -1;
    }
    if _port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }
    let page_table = PageTable::from_token(current_user_token()); 
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    for vpn in start_vpn..end_vpn {
        if page_table.translate(vpn).is_some() {
            return -1;
        }
    }

    let mut perm = MapPermission::empty();
    if _port & 0x1 != 0 {
        perm |= MapPermission::R;
    }
    if _port & 0x2 != 0 {
        perm |= MapPermission::W;
    }
    if _port & 0x4 != 0 {
        perm |= MapPermission::X;
    }

    let mut inner = task::TASK_MANAGER.get_inner().exclusive_access();
    let current_task = inner.get_task();
    let current_ms = current_task.get_ms();
    let map_area = MapArea::new(start_va, end_va, MapType::Framed, perm);
    if let Err(_) = current_ms.push(map_area, None) {
        return -1;
    }

    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    let mut inner = task::TASK_MANAGER.get_inner().exclusive_access(); 
    let current_task = inner.get_task();
    let memory_set = current_task.get_ms();

    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);

    // 检查地址范围是否完全被映射
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    for vpn in start_vpn..end_vpn {
        if memory_set.translate(vpn).is_none() {
            return -1; // 存在未被映射的虚存，返回错误
        }
    }

    // 查找匹配的 MapArea
    if let Some(index) = memory_set.areas.iter().position(|area| {
        let area_start = area.vpn_range.get_start().into();
        let area_end = area.vpn_range.get_end().into();
        start_va == area_start && end_va == area_end
    }) {
        let area = memory_set.areas.remove(index);
        // 取消映射
        for vpn in area.vpn_range {
            memory_set.page_table.unmap(vpn);
        }
        return 0; // 成功
    }

    -1 // 未找到匹配的 MapArea，返回错误
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
