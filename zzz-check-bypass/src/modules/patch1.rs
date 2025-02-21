use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

static HOOK_COUNT: AtomicUsize = AtomicUsize::new(0);
static HOOK_ADDR: AtomicUsize = AtomicUsize::new(0);
static mut PATCH1_INSTANCE: Option<*mut MhyContext<Patch1>> = None;

impl MhyModule for MhyContext<Patch1> {
    unsafe fn init(&mut self) -> Result<()> {
        PATCH1_INSTANCE = Some(self as *mut _ as *mut MhyContext<Patch1>);
        if let Some(addr) = self.addr {
            HOOK_ADDR.store(addr as usize, Ordering::SeqCst);
            let result = self.interceptor.replace(
                addr as usize,
                hkaddr as usize,
                3 as usize
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

unsafe extern "win64" fn hkaddr(_reg: *mut Registers, _: usize, _:usize) ->usize{
    //let count = HOOK_COUNT.fetch_add(1, Ordering::SeqCst);
    print_log(&format!("Patch1 hook triggered"));
    //if count < 1 {
    //    thread::spawn(|| {
    //        unsafe {
    //            rehooker();
    //        }
    //    });
    //}
    0
}

unsafe fn rehooker() {
    if let Some(ctx_ptr) = PATCH1_INSTANCE {
        let ctx = &mut *ctx_ptr;
        let _ = ctx.interceptor.replace(
            HOOK_ADDR.load(Ordering::SeqCst),
            hkaddr as usize,1 as usize
        );
        print_log("Patch1 rehooked");
    }
}