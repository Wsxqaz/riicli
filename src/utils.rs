use serde::{Deserialize, Serialize};
use serde_json::Value;
use windows::core::PCSTR;
use windows::Win32::System::Environment::ExpandEnvironmentStringsA;

pub fn expand_env_strings(string: String) -> String {
    unsafe {
        let mut in_bytes: Vec<u8> = string.clone().into_bytes();
        in_bytes.push(0);
        let in_pcstr: PCSTR = PCSTR(in_bytes.as_ptr() as *const u8);
        let size = ExpandEnvironmentStringsA(in_pcstr, None);
        let mut expanded = vec![0u8; size as usize];
        let _ = ExpandEnvironmentStringsA(in_pcstr, Some(&mut (*expanded)));
        let expanded = expanded
            .iter()
            .take_while(|&&c| c != 0)
            .cloned()
            .collect::<Vec<_>>();
        String::from_utf8(expanded).unwrap().to_string()
    }
}

pub fn t_to_json<'a, T: Serialize + Deserialize<'a>>(t: T) -> Vec<(String, Value)> {
    let mut map = vec![];
    for (key, value) in serde_json::to_value(t).unwrap().as_object().unwrap().iter() {
        map.push((key.to_string(), value.clone()));
    }
    map
}
