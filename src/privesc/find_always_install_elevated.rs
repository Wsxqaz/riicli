use crate::winapi::registry::{read_reg_key, RegKey};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub fn run() -> Vec<RegKey> {
    let path = r"SOFTWARE\Policies\Microsoft\Windows\Installer".to_owned();
    let hklm_values = read_reg_key(HKEY_LOCAL_MACHINE, path.clone());
    let hkcu_values = read_reg_key(HKEY_CURRENT_USER, path.clone());

    log::info!("HKLM: {:?}", hklm_values);
    log::info!("HKCU: {:?}", hkcu_values);
    hklm_values
        .into_iter()
        .chain(hkcu_values.into_iter())
        .collect()
}
