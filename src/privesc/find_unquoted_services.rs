use crate::winapi::acl::is_path_writtable;

use crate::winapi::service::{get_services, Service};

use windows::Win32::System::Wmi::IWbemServices;

pub fn run() -> Vec<(Service, Vec<String>)> {
    log::info!("Loading services");
    let services: Vec<Service> = get_services();
    log::info!("Found {} services", services.len());

    let mut vuln_services: Vec<Service> = Vec::new();

    log::debug!(
        "Checking {} services for unquoted service paths",
        services.len()
    );
    for service in services {
        let path_name = &service.path_name;
        log::debug!("Checking service: {:?}", path_name);
        let is_quoted = path_name.starts_with("\"") || path_name.starts_with("\'");
        let exe_path_contains_space = match path_name.split_once("exe") {
            Some((path, _)) => path.contains(" "),
            None => false,
        };
        if !is_quoted && exe_path_contains_space {
            vuln_services.push(service);
        }
    }
    log::debug!("Found {} unquoted services", vuln_services.len());

    let mut modifiable_services_with_paths: Vec<(Service, Vec<String>)> = Vec::new();
    for service in &vuln_services {
        log::debug!("Found unquoted service: {:?}", &service.path_name);

        let split_path = service.path_name.split(" ");
        let mut paths = Vec::new();

        for path in split_path {
            if paths.len() == 0 {
                paths.push(path.to_string());
            } else {
                let mut ts = (&paths).last().clone().unwrap().to_string();
                ts.push_str(" ");
                ts.push_str(path);
                paths.push(ts);
            }
        }

        let mut modifiable_paths = Vec::new();
        for path in &paths {
            match is_path_writtable(path.to_string()) {
                true => {
                    log::debug!("{} is writtable", path);
                    modifiable_paths.push(path.to_string());
                }
                false => {
                    log::debug!("{} is not writtable", path);
                }
            };
        }

        match modifiable_paths.len() {
            0 => log::debug!("No modifiable paths found"),
            _ => {
                log::debug!(
                    "{}\nFound {} modifiable paths, {:#?}",
                    service.name,
                    modifiable_paths.len(),
                    modifiable_paths
                );
                modifiable_services_with_paths.push((service.clone(), modifiable_paths.clone()));
            }
        }
    }
    return modifiable_services_with_paths;
}
