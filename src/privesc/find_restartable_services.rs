use crate::winapi::service::{get_services, test_service_dacl_permission, Service};
use windows::Win32::System::Wmi::IWbemServices;

pub fn run() -> Vec<Service> {
    let services: Vec<Service> = get_services();
    let mut vuln_services: Vec<Service> = Vec::new();

    for service in services {
        if test_service_dacl_permission(&service, None, "Restart".to_string()) {
            vuln_services.push(service);
        }
    }

    return vuln_services;
}
