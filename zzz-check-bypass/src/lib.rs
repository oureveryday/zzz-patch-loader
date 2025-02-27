#![feature(str_from_utf16_endian)]
#![allow(unused_must_use)]
#![allow(unused_imports)]

mod interceptor;
mod modules;
mod util;

use crate::modules::{MhyContext, Patch1, Patch2};
use lazy_static::lazy_static;
use modules::ModuleManager;
use std::ffi::CString;
use std::panic;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Mutex;
use win_dbg_logger::output_debug_string;
use winapi::um::libloaderapi::{GetModuleFileNameA, LoadLibraryW};
use winapi::um::winuser::{MB_ICONERROR, MB_OK, MessageBoxA};
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
    print_log("Disabled VMP.");
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let module = "GameAssembly.dll";
    util::wait_for_module(module);
    let addrs = util::pattern_scan_multi(
        module,
        "55 41 57 41 56 41 54 56 57 53 48 81 EC A0 00 00 00 48 8D AC 24 80 00 00 00 48 C7 45 18 FE FF FF FF B1 49 31 D2 E8 ?? ?? ?? FF",
    );
    if let Some(addrs) = addrs {
        match addrs.len() {
            0 => panic!("Failed to find pattern"),
            1 => {
                print_log("Found only 1 pattern");
                print_log(&format!("addr1: {:?}", addrs[0]));
                module_manager.enable(MhyContext::<Patch1>::new(Some(addrs[0])));
            }
            _ => {
                print_log("Pattern find success");
                print_log(&format!("addr1: {:?}", addrs[0]));
                print_log(&format!("addr2: {:?}", addrs[1]));
                module_manager.enable(MhyContext::<Patch1>::new(Some(addrs[0])));
                module_manager.enable(MhyContext::<Patch2>::new(Some(addrs[1])));
            }
        }
    } else {
        panic!("Failed to find pattern");
    }
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
        std::thread::spawn(|| thread_func());
    }

    true
}
