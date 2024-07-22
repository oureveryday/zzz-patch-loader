#![feature(str_from_utf16_endian)]

mod interceptor;
mod util;
mod modules;

use std::sync::Mutex;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};
use win_dbg_logger::output_debug_string;
use modules::{ModuleManager};
use crate::modules::{Check, MhyContext};
use lazy_static::lazy_static;

fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

unsafe fn thread_func() {

    match util::try_get_base_address("UnityPlayer.dll") {
        Some(_) => (),
        None => return, 
    };

    #[cfg(debug_assertions)]
    {
    Console::AllocConsole().unwrap();
    }

    print_log("zzz check bypass Init");
    util::disable_memprotect_guard();
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let checkaddr = util::pattern_scan("UnityPlayer.dll","55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC 98 02 00 00 48 8D AC 24 80 00 00 00 C7 45 54 F3 22");
    module_manager.enable(MhyContext::<Check>::new(checkaddr));
}

lazy_static! {
    static ref MODULE_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::default());
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| thread_func());
    }

    true
}
