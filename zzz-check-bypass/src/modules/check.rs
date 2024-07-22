use std::ffi::CString;

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;

pub struct Check;

use win_dbg_logger::output_debug_string;
fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

impl MhyModule for MhyContext<Check> {
    unsafe fn init(&mut self) -> Result<()> {
        self.interceptor.attach(
            self.assembly_base,
            hkcheckaddr,
        )
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Check
    }
}

unsafe extern "win64" fn hkcheckaddr(reg: *mut Registers, _: usize) {
    
    print_log(&format!("rcx: {:x}", (*reg).rcx));
    print_log(&format!("rdx: {:x}", (*reg).rdx));
    print_log(&format!("r8: {:x}", (*reg).r8));
    print_log(&format!("r9: {:x}", (*reg).r9));
}