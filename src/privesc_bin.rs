use crate::privesc::find_always_install_elevated;
use crate::privesc::find_hijackable_dlls_path;
use crate::privesc::find_hijackable_dlls_process;
use crate::privesc::find_modifiable_service_files;
use crate::privesc::find_modifiable_services;
use crate::privesc::find_modifiable_task_files;
use crate::privesc::find_registry_auto_logon;
use crate::privesc::find_restartable_services;
use crate::privesc::find_unattended_install_files;
use crate::privesc::find_unquoted_services;
use crate::privesc::invoke_service_abuse;
use crate::privesc::is_local_admin;

use crate::winapi::acl::ModPathResp;
use crate::winapi::service::Service;
use crate::winapi::tasks::WinTask;
use crate::winapi::wmi::{init_com, init_wmi};

use crate::utils::expand_env_strings;
use windows::Win32::System::Wmi::IWbemServices;

pub async fn run() {
    log::info!("running privilege escalation checks");

    log::info!("Checking if I am admin");
    let am_admin = is_local_admin::run();
    log::info!("Am I admin? {}", am_admin);

    log::info!("Initializing WMI");
    let _ = init_com();
    let _p_svc: IWbemServices = init_wmi().unwrap();
    log::info!("WMI initialized");

    log::info!("Checking for unquoted service paths");
    let unquouted_services: Vec<(Service, Vec<String>)> = find_unquoted_services::run();
    log::info!("Found {} unquoted services", unquouted_services.len());

    log::info!("Checking for restartable services");
    let restartable_services: Vec<Service> = find_restartable_services::run();
    log::info!("Found {} restartable services", restartable_services.len());

    log::info!("Checking for modifiable services");
    let modifiable_service_files: Vec<Service> = find_modifiable_services::run();
    log::info!(
        "Found {} modifiable services",
        modifiable_service_files.len()
    );

    log::info!("Checking for modifiable service paths");
    let _modifiable_service_files: Vec<(Service, ModPathResp)> =
        find_modifiable_service_files::run();
    log::info!(
        "Found {} modifiable service paths",
        _modifiable_service_files.len()
    );

    log::info!("Checking for modifiable task files");
    let modifiable_task_files: Vec<WinTask> = find_modifiable_task_files::run();
    log::info!("found {:?} tasks", modifiable_task_files.len());
    if unquouted_services.len() != 0 {
        log::info!("=== Unquoted services found ===");
        for (service, paths) in unquouted_services {
            log::info!("{:?}", service);
            log::info!("{} - path: {}", service.name, service.path_name);
            log::info!("writtable paths: {:?}", paths);

            log::info!("Attempting to abuse service, press x to skip");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            if input.trim() == "x" {
                continue;
            }

            let _ = invoke_service_abuse::run(&service);

            break;
        }
    }

    let paths = find_hijackable_dlls_path::run();
    log::info!("found {} hijackable paths", paths.len());
    let procs = find_hijackable_dlls_process::run();
    log::info!("found {} hijackable processes", procs.len());

    let f = find_always_install_elevated::run();
    log::info!("found {} always install elevated", f.len());

    let p = find_registry_auto_logon::run();
    log::info!("found {} registry auto logon", p.len());

    let a = find_unattended_install_files::run();
    log::info!("found {} unattended install files", a.len());
}
