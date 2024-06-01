use std::ffi::c_void;

use serde::{Deserialize, Serialize};
use windows::core::{BSTR, HRESULT, PCSTR, PCWSTR, PSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, PSID};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    EqualSid, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SC_HANDLE, TOKEN_GROUPS,
    TOKEN_OWNER, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Services::{
    ChangeServiceConfigA, OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity,
    ENUM_SERVICE_TYPE, SC_MANAGER_CONNECT, SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_START_TYPE,
};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemServices, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE, WBEM_S_FALSE,
};

use crate::winapi::acl::get_acl_sids;
use crate::winapi::token::get_token_privileges;
use crate::winapi::wmi::WMI;
use crate::winapi::wmi::{get_field, init_wmi};

/// Open handle to provided service
pub fn get_service_handle(service: &Service, privs: u32) -> Option<SC_HANDLE> {
    unsafe {
        let sc_control_man = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).unwrap();
        let mut name_cpy = service.name.clone().encode_utf16().collect::<Vec<_>>();
        name_cpy.push(0);
        log::debug!("name_cpy {:x?}", name_cpy);
        let name_pcstr = PCWSTR::from_raw(name_cpy.as_ptr() as *const u16);

        log::debug!("Opening handle to service {:?}", service.name);
        match OpenServiceW(sc_control_man, name_pcstr, privs) {
            // | 0x40000) {
            Ok(handle) => Some(handle),
            Err(e) => {
                log::error!("OpenServiceA Error {:?}", e);
                None
            }
        }
    }
}

/// Get the service's DACL
pub fn get_service_dacl(service: &Service) -> Option<(ACL, PSECURITY_DESCRIPTOR)> {
    let mut _dacl: ACL = ACL {
        AclRevision: 0,
        Sbz1: 0,
        AclSize: 0,
        AceCount: 0,
        Sbz2: 0,
    };

    let _service_handle = get_service_handle(service, 0x20000);
    if _service_handle.is_none() {
        return None;
    }
    let service_handle = _service_handle.unwrap();
    let mut psecuritydescriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut bytes_needed: u32 = 0;

    unsafe {
        let f = QueryServiceObjectSecurity(
            service_handle,
            DACL_SECURITY_INFORMATION.0,
            psecuritydescriptor,
            0,
            &mut bytes_needed,
        );
        log::debug!("QueryServiceObjectSecurity {:?}", f);

        psecuritydescriptor.0 = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
            bytes_needed as usize,
            8,
        )) as *mut c_void;

        let g = QueryServiceObjectSecurity(
            service_handle,
            DACL_SECURITY_INFORMATION.0,
            psecuritydescriptor,
            bytes_needed,
            &mut bytes_needed,
        );
        log::debug!("QueryServiceObjectSecurity {:?}", g);
    }

    Some((_dacl, psecuritydescriptor))
}

#[allow(dead_code)]
/// Set the service binary path for the provided service
pub fn set_service_binary_path(service: &Service, binary_name_str: String) -> () {
    let mut binary_name_vec = binary_name_str.clone().bytes().collect::<Vec<_>>();
    binary_name_vec.push(0);
    let binary_name: PCSTR = PCSTR(binary_name_vec.as_ptr() as *const u8 as *mut u8);
    let service_handle = get_service_handle(service, 0x2).unwrap(); // change config

    unsafe {
        let _ = ChangeServiceConfigA(
            service_handle,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_START_TYPE(SERVICE_NO_CHANGE),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            binary_name,
            None,
            None,
            None,
            None,
            None,
            None,
        );
    }
}

#[allow(dead_code)]
/// Map a permission name to a permission mask
fn permission_to_mask(name: String) -> u32 {
    match name.as_str() {
        "QueryConfig" => 0x00000001,
        "ChangeConfig" => 0x00000002,
        "QueryStatus" => 0x00000004,
        "EnumerateDependents" => 0x00000008,
        "Start" => 0x00000010,
        "Stop" => 0x00000020,
        "PauseContinue" => 0x00000040,
        "Interrogate" => 0x00000080,
        "UserDefinedControl" => 0x00000100,
        "Delete" => 0x00010000,
        "ReadControl" => 0x00020000,
        "WriteDac" => 0x00040000,
        "WriteOwner" => 0x00080000,
        "Synchronize" => 0x00100000,
        "AccessSystemSecurity" => 0x01000000,
        "GenericAll" => 0x10000000,
        "GenericExecute" => 0x20000000,
        "GenericWrite" => 0x40000000,
        "GenericRead" => 0x80000000,
        "AllAccess" => 0x000F01FF,
        _ => 0x00000000,
    }
}

/// Check the service's DACL for the provided permissions
pub fn test_service_dacl_permission(
    service: &Service,
    permissions: Option<Vec<String>>,
    permission_set: String,
) -> bool {
    let target_permissions: Vec<String>;

    if permissions.is_some() {
        target_permissions = permissions.unwrap();
    } else {
        if permission_set == "ChangeConfig" {
            target_permissions = vec![
                "ChangeConfig".to_string(),
                "WriteDac".to_string(),
                "WriteOwner".to_string(),
                "GenericAll".to_string(),
                "GenericWrite".to_string(),
                "AllAccess".to_string(),
            ];
        } else if permission_set == "Restart" {
            target_permissions = vec!["Start".to_string(), "Stop".to_string()];
        } else {
            target_permissions = vec!["GenericAll".to_string(), "AllAccess".to_string()];
        }
    }

    let _get_service_dacl_resp = get_service_dacl(service);
    if _get_service_dacl_resp.is_none() {
        return false;
    }
    let (_dacl, sec_desc): (ACL, PSECURITY_DESCRIPTOR) = _get_service_dacl_resp.unwrap();
    log::debug!("Got service DACL");
    let (_token_privileges, token_groups, _token_owner, _privileges, _handle): (
        *mut TOKEN_PRIVILEGES,
        *mut TOKEN_GROUPS,
        *mut TOKEN_OWNER,
        Vec<String>,
        HANDLE,
    ) = get_token_privileges(None, None);
    log::debug!("Got process token privileges");
    let dacl_sids: Vec<(PSID, u32, PSTR)> = get_acl_sids(sec_desc);
    log::debug!("Got DACL SIDs");

    let mut found_perms: Vec<String> = Vec::new();

    unsafe {
        let groups = (*(token_groups as *mut TOKEN_GROUPS)).Groups.as_ptr();
        for i in 0..((*(token_groups as *mut TOKEN_GROUPS)).GroupCount) {
            let p_group_sid = (*(groups.add(i as usize))).Sid;
            let mut p_str: PWSTR = PWSTR(std::ptr::null_mut());
            let p_p_str: *mut PWSTR = &mut p_str;
            let _conv_resp = ConvertSidToStringSidW(p_group_sid, p_p_str);

            for (psid, mask, _pwstr) in &dacl_sids {
                match EqualSid(p_group_sid, *psid) {
                    Ok(_) => {
                        log::debug!(
                            "current process has group {:?} in dacl w/ mask {:x}",
                            (*p_p_str).to_string(),
                            mask
                        );
                        for permission in &target_permissions {
                            let perm_mask = permission_to_mask(permission.to_string());

                            if mask & perm_mask == perm_mask {
                                log::debug!(
                                    "User has permission {}, perm_mask {:x}, mask {:x}",
                                    permission,
                                    perm_mask,
                                    mask
                                );
                                found_perms.push(permission.to_string());
                            } else {
                                log::debug!(
                                    "User doesn't have permission {}, perm_mask {:x}, mask {:x}",
                                    permission,
                                    perm_mask,
                                    mask
                                );
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    found_perms.sort_unstable();
    found_perms.dedup();

    log::debug!("Found permissions {:?}", found_perms);
    log::debug!("Target permissions {:?}", target_permissions);
    if found_perms.iter().any(|x| target_permissions.contains(&x)) {
        return true;
    } else {
        return false;
    }
}

/// Get all services on the system
pub fn get_services() -> Vec<Service> {
    let mut services: Vec<Service> = Vec::new();
    unsafe {
        let query = BSTR::from("SELECT * FROM Win32_Service");
        let query_lang = BSTR::from("WQL");

        let p_enumerator: IEnumWbemClassObject = match WMI.with(|p_svc| {
            match p_svc.ExecQuery(
                &query_lang,
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            ) {
                Ok(p) => Some(p),
                Err(e) => {
                    log::error!("ExecQuery Error {:?}", e);
                    None
                }
            }
        }) {
            Some(p) => p,
            None => return services,
        };

        let mut objs = [None; 1];
        let mut obj_count: u32 = 0;
        let mut hres: HRESULT = HRESULT(0);

        while hres.0 != WBEM_S_FALSE.0 {
            hres = p_enumerator.Next(WBEM_INFINITE, &mut objs, &mut obj_count);
            match &objs[0] {
                Some(p) => {
                    let __genus = get_field(p, "__GENUS");
                    let __class = get_field(p, "__CLASS");
                    let __superclass = get_field(p, "__SUPERCLASS");
                    let __dynasty = get_field(p, "__DYNASTY");
                    let __relpath = get_field(p, "__RELPATH");
                    let __property_count = get_field(p, "__PROPERTY_COUNT");
                    let __derivation = get_field(p, "__DERIVATION");
                    let __server = get_field(p, "__SERVER");
                    let __namespace = get_field(p, "__NAMESPACE");
                    let __path = get_field(p, "__PATH");
                    let accept_pause = get_field(p, "AcceptPause");
                    let accept_stop = get_field(p, "AcceptStop");
                    let caption = get_field(p, "Caption");
                    let check_point = get_field(p, "CheckPoint");
                    let creation_class_name = get_field(p, "CreationClassName");
                    let delayed_auto_start = get_field(p, "DelayedAutoStart");
                    let description = get_field(p, "Description");
                    let desktop_interact = get_field(p, "DesktopInteract");
                    let display_name = get_field(p, "DisplayName");
                    let error_control = get_field(p, "ErrorControl");
                    let exit_code = get_field(p, "ExitCode");
                    let install_date = get_field(p, "InstallDate");
                    let name = get_field(p, "Name");
                    let path_name = get_field(p, "PathName");
                    let process_id = get_field(p, "ProcessId");
                    let service_specific_exit_code = get_field(p, "ServiceSpecificExitCode");
                    let service_type = get_field(p, "ServiceType");
                    let started = get_field(p, "Started");
                    let start_mode = get_field(p, "StartMode");
                    let start_name = get_field(p, "StartName");
                    let state = get_field(p, "State");
                    let status = get_field(p, "Status");
                    let system_creation_class_name = get_field(p, "SystemCreationClassName");
                    let system_name = get_field(p, "SystemName");
                    let tag_id = get_field(p, "TagId");
                    let wait_hint = get_field(p, "WaitHint");

                    let service = Service {
                        __genus: __genus,
                        __class: __class,
                        __superclass: __superclass,
                        __dynasty: __dynasty,
                        __relpath: __relpath,
                        __property_count: __property_count,
                        __derivation: __derivation,
                        __server: __server,
                        __namespace: __namespace,
                        __path: __path,
                        accept_pause: accept_pause,
                        accept_stop: accept_stop,
                        caption: caption,
                        check_point: check_point,
                        creation_class_name: creation_class_name,
                        delayed_auto_start: delayed_auto_start,
                        description: description,
                        desktop_interact: desktop_interact,
                        display_name: display_name,
                        error_control: error_control,
                        exit_code: exit_code,
                        install_date: install_date,
                        name: name,
                        path_name: path_name,
                        process_id: process_id,
                        service_specific_exit_code: service_specific_exit_code,
                        service_type: service_type,
                        started: started,
                        start_mode: start_mode,
                        start_name: start_name,
                        state: state,
                        status: status,
                        system_creation_class_name: system_creation_class_name,
                        system_name: system_name,
                        tag_id: tag_id,
                        wait_hint: wait_hint,
                    };

                    services.push(service);
                }
                None => {
                    break;
                }
            }

            if hres.0 == WBEM_S_FALSE.0 {
                break;
            }
        }

        log::debug!("Found {} services", services.len());
    }
    return services;
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Service {
    pub __genus: String,
    pub __class: String,
    pub __superclass: String,
    pub __dynasty: String,
    pub __relpath: String,
    pub __property_count: String,
    pub __derivation: String,
    pub __server: String,
    pub __namespace: String,
    pub __path: String,
    pub accept_pause: String,
    pub accept_stop: String,
    pub caption: String,
    pub check_point: String,
    pub creation_class_name: String,
    pub delayed_auto_start: String,
    pub description: String,
    pub desktop_interact: String,
    pub display_name: String,
    pub error_control: String,
    pub exit_code: String,
    pub install_date: String,
    pub name: String,
    pub path_name: String,
    pub process_id: String,
    pub service_specific_exit_code: String,
    pub service_type: String,
    pub started: String,
    pub start_mode: String,
    pub start_name: String,
    pub state: String,
    pub status: String,
    pub system_creation_class_name: String,
    pub system_name: String,
    pub tag_id: String,
    pub wait_hint: String,
}
