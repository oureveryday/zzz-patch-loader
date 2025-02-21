#![feature(str_from_utf16_endian)]
#![allow(unused_must_use)]
#![allow(unused_imports)]

mod interceptor_veh;
mod modules;
mod util;
mod waitforunpack;

use crate::modules::{MhyContext, Patch1};
use lazy_static::lazy_static;
use modules::ModuleManager;
use std::ffi::CString;
use std::panic;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::thread;
use waitforunpack::WaitForUnpack;
use win_dbg_logger::output_debug_string;
use winapi::um::libloaderapi::{GetModuleFileNameA, LoadLibraryW};
use winapi::um::winuser::{MessageBoxA, MB_ICONERROR, MB_OK};
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};

fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);
    println!("{}", &log_str);
    output_debug_string(&log_str);
}

unsafe fn thread_func() {
    #[cfg(debug_assertions)]
    {
        Console::AllocConsole();
    }

    #[cfg(not(debug_assertions))]
    {
        panic::set_hook(Box::new(|panic_info| {
            let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                s
            } else {
                "Unknown panic occurred!\nPlease update bypass.\n(For more info use debug version)"
            };

            let c_message = CString::new(message).unwrap();
            let c_title = CString::new("Panic occurred!").unwrap();

            unsafe {
                MessageBoxA(
                    null_mut(),
                    c_message.as_ptr(),
                    c_title.as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }));
    }

    print_log("zzz check bypass Init");
    let lib_name = "ext.dll\0";
    let lib_name_utf16: Vec<u16> = lib_name.encode_utf16().collect();
    LoadLibraryW(lib_name_utf16.as_ptr());
    print_log("Loaded ext.dll");
    util::disable_memprotect_guard();
    print_log("Waiting for unpack...");
    WaitForUnpack::new().wait_for_unpack(2);
    print_log("Unpacked.");
    util::disable_memprotect_guard();
    print_log("Disabled VMP.");
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let addr1 = util::pattern_scan(
        "UnityPlayer.dll",
        "48 81 EC 98 02 00 00 48 8B 05 ?? ?? ?? 02",
    );
    print_log(&format!("addr1: {:?}", addr1));
    module_manager.enable(MhyContext::<Patch1>::new(addr1));
    print_log(&format!("Hooked."));
}

lazy_static! {
    static ref MODULE_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::default());
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        let mut buffer = vec![0u8; 260];
        let len = GetModuleFileNameA(
            null_mut(),
            buffer.as_mut_ptr() as *mut i8,
            buffer.len() as u32,
        );
        if len > 0 {
            let exe_path = String::from_utf8_lossy(&buffer[..len as usize]);
            let exe_name = Path::new(exe_path.as_ref())
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            if exe_name != "ZenlessZoneZeroBeta.exe" {
                print_log("Patch not running in game, exiting...");
                return true;
            }
        }
        thread::spawn(|| thread_func());
    }

    true
}
