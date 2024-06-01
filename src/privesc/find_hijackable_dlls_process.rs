use crate::winapi::process::{load_processes, Process};
use crate::winapi::registry::{read_reg_key, RegKey};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

pub fn run() -> Vec<Process> {
    let processes: Vec<Process> = load_processes();
    log::info!("Found {} processes", processes.len());
    let _hijackable_dlls: Vec<Process> = Vec::new();

    let known_dll_key_name =
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs".to_owned();
    let known_dlls: Vec<RegKey> = read_reg_key(HKEY_LOCAL_MACHINE, known_dll_key_name.clone());
    log::info!(
        "Found {} known dlls in HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
        known_dlls.len()
    );

    for process in processes {
        for module in process.module_info {
            if !known_dlls.iter().any(|x| {
                let r = module
                    .file_name
                    .to_lowercase()
                    .contains(&x.value.to_lowercase());
                // log::info!("Checking module: {:?} for dll {:?}, resp {}", module.file_name, x, r);
                r
            }) {
                // log::info!("Found not known module {:?} in {:?}", module, process.name,);

                let base_path = std::path::Path::new(&process.executable_path)
                    .parent()
                    .unwrap()
                    .to_str()
                    .unwrap();
                let module_name = std::path::Path::new(&module.file_name)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap();

                let check_str = format!("{}\\{}", base_path, module_name);
                let check_path = std::path::Path::new(&check_str);

                // log::info!("Checking path: {:?}", check_path);
                if !check_path.exists() {
                    log::info!(
                        "Found hijackable module {:?} in {:?}, process exe path: {:?}",
                        module.file_name,
                        process.name,
                        process.executable_path
                    );
                }
            }
        }
    }

    vec![]
}
