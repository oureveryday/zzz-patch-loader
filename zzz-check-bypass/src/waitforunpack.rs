use anyhow::{bail, Result};
use core::iter::once;
use ilhook::x64::{
    CallbackOption, HookFlags, HookPoint, HookType, Hooker, JmpBackRoutine,
};
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::Duration;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

static HOOK_TRIGGERED_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "win64" fn hook_callback(_regs: *mut ilhook::x64::Registers, _ctx: usize) {
    HOOK_TRIGGERED_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub struct WaitForUnpack {
    pub hooks: Vec<HookPoint>,
}

impl WaitForUnpack {
    pub const fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub unsafe fn attach(&mut self, addr: usize, routine: JmpBackRoutine) -> Result<()> {
        let hooker = Hooker::new(
            addr,
            HookType::JmpBack(routine),
            CallbackOption::None,
            0,
            HookFlags::empty(),
        );

        let Ok(hook_point) = hooker.hook() else {
            bail!("Failed to attach 0x{addr:X}")
        };

        self.hooks.push(hook_point);
        Ok(())
    }

    fn wide_str(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(once(0)).collect()
    }

    pub unsafe fn wait_for_unpack(&mut self, hook_count: usize) -> Result<bool> {
        let kernel32 = WaitForUnpack::wide_str("kernel32.dll");
        let ntdll = GetModuleHandleW(PCWSTR::from_raw(kernel32.as_ptr())).unwrap();
        let proc_addr = GetProcAddress(
            ntdll,
            PCSTR::from_raw(c"GetSystemTimeAsFileTime".to_bytes_with_nul().as_ptr()),
        )
        .unwrap();

        self.attach(proc_addr as usize, hook_callback)?;

        while HOOK_TRIGGERED_COUNT.load(Ordering::SeqCst) < hook_count {
            sleep(Duration::from_millis(1));
        }
        Ok(true)
    }
}