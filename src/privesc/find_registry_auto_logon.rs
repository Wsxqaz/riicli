use crate::winapi::registry::{read_reg_key, RegKey};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

pub fn run() -> Vec<RegKey> {
    let key: String = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon".to_string();
    let keys = read_reg_key(HKEY_LOCAL_MACHINE, key.clone());
    log::debug!("Found {} values for {}", keys.len(), key.clone());
    if keys.clone().iter().any(|x| {
        x.name
            .to_lowercase()
            .contains(&"AutoAdminLogon".to_string().to_lowercase())
    }) {
        for key in &keys {
            log::info!("Key: {:?}, Value: {:?}", key.name, key.value);
        }

        keys
    } else {
        Vec::new()
    }
}
