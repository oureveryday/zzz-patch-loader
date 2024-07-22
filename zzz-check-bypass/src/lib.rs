#![feature(str_from_utf16_endian)]

mod interceptor;
mod util;
mod modules;
use std::{sync::Mutex, time::Duration};
use lazy_static::lazy_static;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};
use win_dbg_logger::output_debug_string;
use anyhow::Result;
use ilhook::x64::Registers;
use crate::interceptor::Interceptor;
use modules::{ModuleManager};
use crate::modules::{Check, MhyContext, ModuleType};
fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

unsafe fn thread_func() {
    #[cfg(debug_assertions)]
    {
    Console::AllocConsole().unwrap();
    }

    print_log("zzz check bypass Init");
    util::disable_memprotect_guard();
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let checkaddr = util::pattern_scan("UnityPlayer.dll","40 53 55 57 41 55 41 57 48 83 EC 40 48 89 74 24");
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
