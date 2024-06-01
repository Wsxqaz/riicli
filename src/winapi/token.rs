use std::ffi::c_void;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{GetLastError, FALSE, GENERIC_ALL, HANDLE, LUID};
#[allow(unused_imports)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeNameA, LookupPrivilegeValueA,
    TokenGroups, TokenOwner, TokenPrivileges, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED,
    TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_OWNER,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::WindowsProgramming::GetComputerNameA;

use crate::winapi::acl::{get_sid_names, SidNames};

pub fn get_token_info<T>(handle: *mut HANDLE, info_class: TOKEN_INFORMATION_CLASS) -> *mut T {
    let mut dw_size: u32 = 0;
    let token_info: *mut T;

    unsafe {
        // get buffer size
        log::debug!("GetTokenInformation");
        let get_buffer_resp = GetTokenInformation(*handle, info_class, None, dw_size, &mut dw_size);
        log::debug!("GetTokenInformation {:?} ", get_buffer_resp);
        log::debug!("GetTokenInformation Error {:?}", GetLastError());
        log::debug!("GetTokenInformation Success");

        // allocate buffer
        log::debug!("Allocating buffer {}", dw_size);
        token_info = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
            dw_size as usize,
            8,
        )) as *mut T;
        log::debug!("Allocate buffer Success");

        // info to buffer
        log::debug!("GetTokenInformation");
        let get_load_resp = GetTokenInformation(
            *handle,
            info_class,
            Some(token_info as *mut c_void),
            dw_size,
            &mut dw_size,
        );
        log::debug!("GetTokenInformation {:?}", get_load_resp);
        log::debug!("GetTokenInformation Error {:?}", GetLastError());
        log::debug!("GetTokenInformation Success");
    }

    token_info
}

pub fn token_groups_to_names(groups: *mut TOKEN_GROUPS) -> Vec<SidNames> {
    unsafe {
        let mut resp = Vec::new();
        let group_count = (*(groups as *mut TOKEN_GROUPS)).GroupCount;
        log::debug!("Found {} groups in token", group_count);
        for i in 0..group_count {
            let sid = (*(*(groups as *mut TOKEN_GROUPS))
                .Groups
                .as_ptr()
                .add(i as usize))
            .Sid;
            let sid_name = get_sid_names(sid);
            resp.push(sid_name);
        }
        return resp;
    }
}

pub fn token_owner_to_name(owner: *mut TOKEN_OWNER) -> SidNames {
    unsafe {
        let sid = (*(owner as *mut TOKEN_OWNER)).Owner;
        get_sid_names(sid)
    }
}

/// Get the privileges and groups for provided handle
/// If no handle is provided, the current process is used
/// If no privileges are provided, all privileges are returned
pub fn get_token_privileges(
    in_handle: Option<HANDLE>,
    in_privs: Option<TOKEN_ACCESS_MASK>,
) -> (
    *mut TOKEN_PRIVILEGES,
    *mut TOKEN_GROUPS,
    *mut TOKEN_OWNER,
    Vec<String>,
    HANDLE,
) {
    unsafe {
        let mut handle: HANDLE = HANDLE(0);

        match in_handle {
            None => {
                let privs = match in_privs {
                    None => {
                        log::debug!("no privs specified, using TOKEN_ALL_ACCESS");
                        TOKEN_ALL_ACCESS
                    }
                    Some(p) => {
                        log::debug!("privs specified, using provided value");
                        p | TOKEN_QUERY
                    }
                };
                log::debug!("OpenProcessToken");
                let open_resp = OpenProcessToken(GetCurrentProcess(), privs, &mut handle);
                log::debug!("OpenProcessToken {:?} ", open_resp);
                log::debug!("OpenProcessToken Success");
            }
            Some(h) => {
                log::debug!("Using provided handle");
                handle = h;
            }
        };

        log::debug!("handle {:?}", handle);

        let token_privileges: *mut TOKEN_PRIVILEGES;
        let token_groups: *mut TOKEN_GROUPS;
        let token_owner: *mut TOKEN_OWNER;

        token_privileges = get_token_info::<TOKEN_PRIVILEGES>(&mut handle, TokenPrivileges);
        token_groups = get_token_info::<TOKEN_GROUPS>(&mut handle, TokenGroups);
        token_owner = get_token_info::<TOKEN_OWNER>(&mut handle, TokenOwner);

        let group_count = (*(token_groups as *mut TOKEN_GROUPS)).GroupCount;
        log::debug!("Found {} groups in token", group_count);

        let privileges_count = (*(token_privileges as *mut TOKEN_PRIVILEGES)).PrivilegeCount;
        log::debug!("Found {} privileges in token", privileges_count);

        let privlege_strings: Vec<String> = read_token_privileges(token_privileges);

        (
            token_privileges,
            token_groups,
            token_owner,
            privlege_strings,
            handle,
        )
    }
}

fn read_token_privileges(token_privileges: *mut TOKEN_PRIVILEGES) -> Vec<String> {
    unsafe {
        let mut resp = Vec::new();
        let privileges = (*(token_privileges as *mut TOKEN_PRIVILEGES))
            .Privileges
            .as_ptr();

        let mut computer_name_size = 0;
        let mut computer_name: PSTR = PSTR(std::ptr::null_mut());

        log::debug!("GetComputerNameA");
        let get_name_size_resp =
            GetComputerNameA(PSTR(std::ptr::null_mut()), &mut computer_name_size);
        log::debug!("GetComputerNameA get size {:?}", get_name_size_resp);
        log::debug!("GetComputerNameA get size error {:?}", GetLastError());

        // allocate buffer
        log::debug!("Allocating buffer {}", computer_name_size);
        computer_name.0 = std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
            computer_name_size as usize,
            8,
        )) as *mut u8;
        log::debug!("Allocate buffer Success");

        log::debug!("GetComputerNameA");
        let get_name_resp = GetComputerNameA(computer_name, &mut computer_name_size);
        log::debug!("GetComputerNameA load {:?}", get_name_resp);
        log::debug!("GetComputerNameA load error {:?}", GetLastError());
        log::debug!("Computer Name: {:?}", computer_name.to_string());
        let privileges_count = (*(token_privileges as *mut TOKEN_PRIVILEGES)).PrivilegeCount;
        for i in 0..privileges_count {
            let mut p_str: PSTR = PSTR(std::ptr::null_mut());
            let mut cch_name: u32 = 1;
            let tmp: PSTR = PSTR(&[0u8; 1] as *const u8 as *mut u8);
            let pluid = &((*(privileges.add(i as usize))).Luid);
            log::debug!("LookupPrivilegeNameW");
            let _conv_size_resp =
                LookupPrivilegeNameA(PCSTR(computer_name.as_ptr()), pluid, tmp, &mut cch_name);
            log::debug!("LookupPrivilegeNameW {:?}", _conv_size_resp);
            log::debug!("LookupPrivilegeNameW Error {:?}", GetLastError());

            log::debug!("Allocating buffer {}", cch_name);
            p_str.0 = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                cch_name as usize,
                8,
            )) as *mut u8;
            log::debug!("Allocate buffer Success");

            log::debug!("LookupPrivilegeNameW");
            let _conv_resp =
                LookupPrivilegeNameA(PCSTR(computer_name.as_ptr()), pluid, p_str, &mut cch_name);
            log::debug!("LookupPrivilegeNameW {:?}", _conv_resp);
            log::debug!("LookupPrivilegeNameW Error {:?}", GetLastError());

            log::debug!("privilege {}: {:?}", i, p_str.to_string());
            resp.push(p_str.to_string().unwrap_or("".to_string()));
        }
        return resp;
    }
}

#[allow(dead_code)]
/// Enable a privilege for the current process
pub fn add_token_privilege(in_handle: Option<HANDLE>, privilege: String, add: bool) -> () {
    unsafe {
        let mut handle: HANDLE = HANDLE(0);
        match in_handle {
            None => {
                log::debug!("OpenProcessToken");
                let _ = OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_ACCESS_MASK(GENERIC_ALL.0),
                    &mut handle,
                );
            }
            Some(h) => {
                log::debug!("Using provided handle");
                handle = h;
            }
        };
        log::debug!("handle {:?}", handle);

        let mut luid: LUID = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        let mut priv_bytes = privilege.into_bytes();
        let _ = priv_bytes.push(0);
        let priv_pcstr = PCSTR(priv_bytes.as_ptr() as *const u8);
        let privv: *mut TOKEN_PRIVILEGES =
            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<TOKEN_PRIVILEGES>(),
                8,
            )) as *mut TOKEN_PRIVILEGES;
        log::debug!("LookupPrivilegeValueA");
        log::debug!("luid {:?}", luid);
        let lookup_resp = LookupPrivilegeValueA(None, priv_pcstr, &mut luid);
        log::debug!("luid {:?}", luid);
        log::debug!("LookupPrivilegeValueA {:?}", lookup_resp);
        log::debug!("LookupPrivilegeValueA Error {:?}", GetLastError());

        (*privv).PrivilegeCount = 1;
        (*privv).Privileges[0].Attributes = match add {
            false => SE_PRIVILEGE_REMOVED,
            true => SE_PRIVILEGE_ENABLED,
        };
        (*privv).Privileges[0].Luid = luid;

        log::debug!("AdjustTokenPrivileges");
        let adjust_token_resp = AdjustTokenPrivileges(
            handle,
            FALSE,
            Some(privv),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );
        log::debug!("AdjustTokenPrivileges {:?}", adjust_token_resp);
        log::debug!("AdjustTokenPrivileges Error {:?}", GetLastError());
    }
}
