use crate::winapi::token::get_token_info;

use windows::core::PWSTR;
use windows::Win32::Foundation::{GENERIC_ALL, HANDLE, PSID};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    AllocateAndInitializeSid, EqualSid, TokenGroups, SECURITY_NT_AUTHORITY,
    SID_IDENTIFIER_AUTHORITY, TOKEN_ACCESS_MASK, TOKEN_GROUPS,
};
use windows::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn run() -> bool {
    let mut h_token: HANDLE = HANDLE(0);
    let mut builtin_admin_group_sid: PSID = PSID(std::ptr::null_mut());
    let nt_authority: SID_IDENTIFIER_AUTHORITY = SECURITY_NT_AUTHORITY;

    unsafe {
        log::debug!("OpenProcessToken");
        let open_resp = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(GENERIC_ALL.0),
            &mut h_token,
        );
        log::debug!("OpenProcessToken {:?} ", open_resp);
        log::debug!("OpenProcessToken Success");

        let token_groups = get_token_info::<TOKEN_GROUPS>(&mut h_token, TokenGroups);

        match AllocateAndInitializeSid(
            &nt_authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut builtin_admin_group_sid,
        ) {
            Ok(_) => log::debug!("AllocateAndInitializeSid Success"),
            Err(e) => {
                log::error!("AllocateAndInitializeSid Error {:?}", e);
                return false;
            }
        };

        let group_count = (*(token_groups as *mut TOKEN_GROUPS)).GroupCount;
        log::info!("Found {} groups in token", group_count);
        let groups = (*(token_groups as *mut TOKEN_GROUPS)).Groups.as_ptr();
        for i in 0..(group_count) {
            let p_group_sid = (*(groups.add(i as usize))).Sid;
            let mut p_str: PWSTR = PWSTR(std::ptr::null_mut());
            let p_p_str: *mut PWSTR = &mut p_str;
            let _conv_resp = ConvertSidToStringSidW(p_group_sid, p_p_str);

            match EqualSid(p_group_sid, builtin_admin_group_sid) {
                Ok(_) => {
                    log::info!("Sid {:?} is admin", p_str.to_string().unwrap());
                    return true;
                }
                Err(_) => (),
            }
        }
    }

    return false;
}
