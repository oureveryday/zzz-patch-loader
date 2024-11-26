use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct Patch1;

use win_dbg_logger::output_debug_string;
fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

static mut PATCH1_INSTANCE: Option<*mut MhyContext<Patch1>> = None;

impl MhyModule for MhyContext<Patch1> {
    unsafe fn init(&mut self) -> Result<()> {
        PATCH1_INSTANCE = Some(self as *mut _ as *mut MhyContext<Patch1>);
        if let Some(addr) = self.addr {
            let result = self.interceptor.replace(
                addr as usize,
                hkaddr,
            );
            print_log(&format!("Patch1 hooked"));
            result
        } else {
            Err(anyhow::anyhow!("addr is None"))
        }
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Patch1
    }
}

unsafe fn unhooker()
{
    loop{
        thread::sleep(Duration::from_secs(3));
        if let Some(instance_ptr) = PATCH1_INSTANCE {
            let instance = &mut *instance_ptr;
            instance.interceptor.detach();
            print_log(&format!("Detached Patch1"));
            break;
        } else {
            print_log(&format!("Failed to detach"));
        }
        
    }
}

unsafe extern "win64" fn hkaddr(_reg: *mut Registers, _: usize, _:usize) ->usize{
    print_log(&format!("Patch1 hook triggered"));
    thread::spawn(|| {
        unsafe {
            unhooker();
        }
    });
    0
}