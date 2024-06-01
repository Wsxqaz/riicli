use crate::winapi::acl::{get_modifiable_path, ModPathResp, WRITTABLE_PERMS};

use crate::winapi::service::{get_services, Service};
use crate::winapi::token::get_token_privileges;

use windows::Win32::Foundation::{HANDLE, PSID};
use windows::Win32::Security::{EqualSid, TOKEN_GROUPS, TOKEN_OWNER, TOKEN_PRIVILEGES};
use windows::Win32::System::Wmi::IWbemServices;

pub fn run() -> Vec<(Service, ModPathResp)> {
    let services: Vec<Service> = get_services();
    let (_privs, groups, _, _, _tk_handle): (
        *mut TOKEN_PRIVILEGES,
        *mut TOKEN_GROUPS,
        *mut TOKEN_OWNER,
        Vec<String>,
        HANDLE,
    ) = get_token_privileges(None, None);
    let mut cur_groups: Vec<PSID> = Vec::new();
    let mut modifiable_service_files: Vec<(Service, ModPathResp)> = Vec::new();

    unsafe {
        for i in 0..(*groups).GroupCount {
            cur_groups.push((*(*groups).Groups.as_ptr().add(i as usize)).Sid);
        }
    }

    for service in &services {
        if service.start_name != "LocalSystem" {
            continue;
        }

        log::debug!("");
        log::debug!("====================================");
        log::debug!("");
        log::debug!("checking service: {:?}", service.name);
        log::debug!("run as: {:?}", service.start_name);
        log::debug!("service path: {:?}", service.path_name);

        let mut modifiable_paths: Vec<ModPathResp> = get_modifiable_path(&service.path_name);
        modifiable_paths.sort();
        modifiable_paths.dedup();

        log::debug!("found {} sids with mod perms", modifiable_paths.len());

        for resp in modifiable_paths {
            log::debug!(
                "{:?} | {}, {}\\{} -- {:?}",
                resp.clone().path.to_string(),
                resp.clone().sid_str.unwrap_or("".to_string()),
                resp.clone().sid_domain.unwrap_or("".to_string()),
                resp.clone().sid_name.unwrap_or("".to_string()),
                resp.clone()
                    .mask_strings
                    .clone()
                    .iter()
                    .filter(|x| WRITTABLE_PERMS.contains(&(x as &str)))
                    .map(|x| (*x).clone())
                    .collect::<Vec<String>>()
            );
            for group in &cur_groups {
                unsafe {
                    match EqualSid(resp.sid, *group) {
                        Ok(_) => {
                            modifiable_service_files.push((service.clone(), resp.clone()));
                            break;
                        }
                        Err(_) => (),
                    }
                }
            }
        }
    }
    return modifiable_service_files;
}
