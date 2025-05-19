//! Process management syscalls
use crate::{config::PAGE_SIZE, mm::{PageTable,VirtAddr,VirtPageNum,MapArea,MapPermission,MapType}, syscall::{NUM_SYSCALL_EXIT, NUM_SYSCALL_GET_TIME, NUM_SYSCALL_MMAP, NUM_SYSCALL_MUNMAP, NUM_SYSCALL_SBRK, NUM_SYSCALL_TRACE, NUM_SYSCALL_WRITE, NUM_SYSCALL_YIELD}, task::{change_program_brk, exit_current_and_run_next, suspend_current_and_run_next}, timer::get_time_us};
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
    unsafe{
        NUM_SYSCALL_EXIT += 1;
    }
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    unsafe{
        NUM_SYSCALL_YIELD += 1;
    }
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    unsafe{
        NUM_SYSCALL_GET_TIME += 1;
    }
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
    unsafe{
        NUM_SYSCALL_TRACE += 1;
    }
    match _trace_request{
        0 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id as usize);
            let vpn = va.floor();
            let pte = page_table.translate(vpn).expect("Failed to translate virtual address");
            let base = pte.ppn().get_bytes_array().as_mut_ptr(); 
            let ptr = unsafe{
                base.add(va.page_offset())
            };
            unsafe{
                *ptr as isize
            }
        },
        1 => {
            let page_table = PageTable::from_token(current_user_token());
            let va = VirtAddr::from(_id as usize);
            let vpn = va.floor();
            let pte = page_table.translate(vpn).expect("Failed to translate virtual address");
            if !pte.writable() {
                return -1;
            }
            let base = pte.ppn().get_bytes_array().as_mut_ptr(); 
            let ptr = unsafe{
                base.add(va.page_offset())
            };
            unsafe {
                *ptr = _data as u8;
            }
            0
        },
        2 => {
            unsafe{
                match _id{
                    64 => NUM_SYSCALL_WRITE as isize,
                    93 => NUM_SYSCALL_EXIT as isize,
                    124 => NUM_SYSCALL_YIELD as isize,
                    169 => NUM_SYSCALL_GET_TIME as isize,
                    214 => NUM_SYSCALL_SBRK as isize,
                    215 => NUM_SYSCALL_MUNMAP as isize,
                    222 => NUM_SYSCALL_MMAP as isize,
                    410 => NUM_SYSCALL_TRACE as isize,
                    _ => -1
                }
            }
        },
        _ => -1
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    unsafe{
        NUM_SYSCALL_MMAP += 1;
    }
    if _start % PAGE_SIZE != 0{
        return -1
    }

    let mut page_table = PageTable::from_token(current_user_token()); 
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);
    let start_vpn = VirtPageNum::from(start_va);
    let page_count = (_len + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0.. page_count{
        if page_table.query(start_vpn + i) {
            return -1; 
        }
    }
    let mut perm = MapPermission::empty();
    if _port & 0x1 != 0 { perm |= MapPermission::R; }
    if _port & 0x2 != 0 { perm |= MapPermission::W; }
    if _port & 0x4 != 0 { perm |= MapPermission::X; }
    if _port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }

    let mut ma = MapArea::new(start_va, end_va, MapType::Framed, MapPermission::from_bits(_port as u8).unwrap());
    for i in 0..page_count {
        ma.map_one(&mut page_table, start_vpn + i);
    }
    0

}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    unsafe{
        NUM_SYSCALL_MUNMAP += 1;
    }
    let mut page_table = PageTable::from_token(current_user_token()); 
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(_start + _len);
    let start_vpn = VirtPageNum::from(start_va);
    let end_vpn = end_va.ceil();


    let mut vpn = start_vpn;
    while vpn < end_vpn {
        page_table.unmap(vpn);
        vpn = vpn + 1;
    }
    0

}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    unsafe{
        NUM_SYSCALL_SBRK += 1;
    }
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
