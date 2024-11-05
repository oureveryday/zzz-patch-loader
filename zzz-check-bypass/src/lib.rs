#![feature(str_from_utf16_endian)]

mod interceptor;
mod util;
mod modules;

use std::sync::Mutex;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};
use winapi::um::libloaderapi::{LoadLibraryW};
use win_dbg_logger::output_debug_string;
use modules::{ModuleManager};
use crate::modules::{Patch1, Patch2, MhyContext};
use lazy_static::lazy_static;

fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);
    println!("{}",&log_str);
    output_debug_string(&log_str);
}

unsafe fn thread_func() {

    #[cfg(debug_assertions)]
    {
    Console::AllocConsole();
    }

    print_log("zzz check bypass Init");
    let lib_name = "ext.dll\0";
    let lib_name_utf16: Vec<u16> = lib_name.encode_utf16().collect();
    LoadLibraryW(lib_name_utf16.as_ptr());
    print_log("Loaded ext.dll");
    util::disable_memprotect_guard();
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let addr1 = util::pattern_scan("UnityPlayer.dll","55 41 56 56 57 53 48 81 EC 00 01 00 00 48 8D AC 24 80 00 00 00 C7 45 7C 00 00 00 00");
    let addr2 = util::pattern_scan("UnityPlayer.dll","48 81 EC 98 02 00 00 48 8B 05 BA 26 05 02");
    print_log(&format!("addr1: {:?}", addr1));
    print_log(&format!("addr2: {:?}", addr2));
    module_manager.enable(MhyContext::<Patch1>::new(addr1));
    module_manager.enable(MhyContext::<Patch2>::new(addr2));
    print_log(&format!("Hooked."));
}

lazy_static! {
    static ref MODULE_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::default());
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        thread_func()
    }

    true
}
