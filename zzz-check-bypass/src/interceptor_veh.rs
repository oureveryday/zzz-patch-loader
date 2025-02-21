use anyhow::{bail, Result};
use lazy_static::lazy_static;
use std::ptr;
use std::sync::Mutex;
use std::sync::mpsc::{self, Sender};
use std::thread;
use win_dbg_logger::output_debug_string;
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{
    EXCEPTION_POINTERS, PAGE_EXECUTE_READ, PAGE_GUARD, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_SINGLE_STEP,
};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

struct AsyncLogger {
    sender: Sender<String>,
}

impl AsyncLogger {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                println!("{}", msg);
            }
        });
        Self { sender: tx }
    }

    fn log(&self, msg: String) {
        let _ = self.sender.send(msg);
    }
}

lazy_static! {
    static ref LOGGER: AsyncLogger = AsyncLogger::new();
}

fn print_log(s: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", s);
    LOGGER.log(log_str.clone());
}
pub struct VehHook {
    pub og_addr: usize,
    pub hook_addr: usize,
    pub enabled: bool,
    pub call_orig: bool,
    pub hook_count: usize,
    pub current_hook_count: usize,
}

impl VehHook {
    pub unsafe fn enable(&mut self) -> Result<()> {
        let mut old_prot = 0;
        let res = VirtualProtect(
            self.og_addr as *mut _,
            1,
            PAGE_EXECUTE_READ | PAGE_GUARD,
            &mut old_prot,
        );
        if res != 0 {
            self.enabled = true;
            Ok(())
        } else {
            bail!("Failed to enable VEH hook at 0x{:X}", self.og_addr)
        }
    }

    pub unsafe fn disable(&mut self) -> Result<()> {
        let mut old_prot = 0;
        let res = VirtualProtect(self.og_addr as *mut _, 1, PAGE_EXECUTE_READ, &mut old_prot);
        if res != 0 {
            self.enabled = false;
            Ok(())
        } else {
            bail!("Failed to disable VEH hook at 0x{:X}", self.og_addr)
        }
    }
}

static mut VEH_HOOKS: Vec<VehHook> = Vec::new();

pub struct InterceptorVeh {
    pub handler: *mut winapi::ctypes::c_void,
}

impl InterceptorVeh {
    pub unsafe fn new() -> Result<Self> {
        let handler = AddVectoredExceptionHandler(1, Some(veh_handler));
        if handler.is_null() {
            bail!("Failed to register VEH handler");
        }
        Ok(Self { handler })
    }

    #[allow(dead_code)]
    pub unsafe fn replace(&mut self, addr: usize, hook_addr: usize, hook_count: usize) -> Result<()> {
        let mut veh_hook = VehHook {
            og_addr: addr,
            hook_addr,
            enabled: false,
            call_orig: false,
            hook_count: hook_count,
            current_hook_count: 0,
        };
        veh_hook.enable()?;
        VEH_HOOKS.push(veh_hook);
        Ok(())
    }

    pub unsafe fn detach(&mut self) -> Result<()> {
        {
            for hook in VEH_HOOKS.iter_mut() {
                hook.disable()?;
            }
            VEH_HOOKS.clear();
        }
        if !self.handler.is_null() {
            RemoveVectoredExceptionHandler(self.handler);
            self.handler = ptr::null_mut();
        }
        Ok(())
    }
}

extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let result = std::panic::catch_unwind(|| {
        unsafe {
            let exception_record = (*exception_info).ExceptionRecord;
            let code = (*exception_record).ExceptionCode;
            if code == STATUS_GUARD_PAGE_VIOLATION {
                for hook in VEH_HOOKS.iter_mut() {
                    if hook.enabled && ((*exception_record).ExceptionAddress as usize) == hook.og_addr {
                        if !hook.call_orig {
                            hook.current_hook_count += 1;
                            (*(*exception_info).ContextRecord).Rip = hook.hook_addr as u64;
                            if hook.current_hook_count >= hook.hook_count {
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }
                    }
                }   
                (*(*exception_info).ContextRecord).EFlags |= 0x100;  // Set single step flag to avoid PAGE_GUARD being deleted
                return EXCEPTION_CONTINUE_EXECUTION;
            } else if code == STATUS_SINGLE_STEP {
                for hook in VEH_HOOKS.iter_mut() {
                    let mut old_prot = 0;
                    VirtualProtect(
                        hook.og_addr as *mut _,
                        1,
                        PAGE_EXECUTE_READ | PAGE_GUARD,
                        &mut old_prot,
                    );
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            EXCEPTION_CONTINUE_SEARCH
        }
    });
    match result {
        Ok(ret) => ret,
        Err(_) => {
            print_log("Panic occurred in VEH handler. Continuing execution.");
            EXCEPTION_CONTINUE_EXECUTION
        }
    }
}