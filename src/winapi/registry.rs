use windows::core::{PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Win32::System::Registry::RegOpenKeyExW;
use windows::Win32::System::Registry::{
    RegEnumValueA, RegEnumValueW, RegQueryInfoKeyW, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS,
    REG_SAM_FLAGS,
};

#[derive(Debug, Clone)]
pub struct RegKey {
    pub path: String,
    pub name: String,
    pub value: String,
}

pub fn read_reg_key(registry: HKEY, key: String) -> Vec<RegKey> {
    let mut key_name_vec = key.encode_utf16().collect::<Vec<_>>();
    key_name_vec.push(0);

    let mut resps: Vec<RegKey> = vec![];
    let mut reg_key: HKEY = HKEY(0);
    let _ = unsafe {
        RegOpenKeyExW(
            registry,
            PCWSTR::from_raw(key_name_vec.as_ptr()),
            0,
            REG_SAM_FLAGS(0x0001), // KEY_QUERY_VALUE
            &mut reg_key as *mut HKEY,
        )
    };

    let mut num_values = 0;
    let _ = unsafe {
        RegQueryInfoKeyW(
            reg_key,
            PWSTR::null(),
            None,
            None,
            None,
            None,
            None,
            Some(&mut num_values),
            Some(&mut 128),
            Some(&mut 128),
            None,
            None,
        )
    };
    log::debug!("num_values: {}", num_values);

    let mut value_name_buffer = vec![0u8; 1024];
    let mut value_data_buffer = vec![0u8; 1024];
    for i in 0..num_values {
        log::debug!("i: {}", i);
        let mut value_name_buffer_len = value_name_buffer.len() as u32;
        let mut value_data_buffer_len = value_data_buffer.len() as u32;

        let enum_resp = unsafe {
            RegEnumValueA(
                reg_key,
                i,
                PSTR(value_name_buffer.as_mut_ptr()),
                &mut value_name_buffer_len,
                None,
                None,
                Some(value_data_buffer.as_mut_ptr()),
                Some(&mut value_data_buffer_len),
            )
        };
        log::debug!("enum_resp: {:?}", enum_resp);

        let value_name =
            String::from_utf8_lossy(&value_name_buffer[..value_name_buffer_len as usize])
                .to_string()
                .trim_matches(char::from(0))
                .to_string();
        let value_data =
            String::from_utf8_lossy(&value_data_buffer[..value_data_buffer_len as usize])
                .to_string()
                .trim_matches(char::from(0))
                .to_string();

        let reg_dll = RegKey {
            path: key.clone(),
            name: value_name,
            value: value_data,
        };
        resps.push(reg_dll);
    }

    resps
}
