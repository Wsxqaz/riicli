use crate::winapi::token::get_token_privileges;
use std::ffi::c_void;
use std::string::FromUtf8Error;
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{
    BOOL, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, PSID,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;

#[allow(unused_imports)]
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetFileSecurityA, GetSecurityDescriptorDacl,
    LookupAccountSidA, LookupAccountSidW, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, FAILED_ACCESS_ACE_FLAG,
    INHERITED_ACE, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE,
    PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR, SE_DACL_DEFAULTED, SE_DACL_PRESENT, SID,
    SID_NAME_USE, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_ALARM_ACE,
};

#[allow(unused_imports)]
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED, SYSTEM_ALARM_ACE_TYPE,
};

#[allow(unused_imports)]
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_CREATE_PIPE_INSTANCE,
    FILE_DELETE_CHILD, FILE_EXECUTE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_READ_EA, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    READ_CONTROL, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};

#[allow(dead_code)]
fn ace_type_to_string(ace_header: ACE_HEADER) -> String {
    match ace_header.AceType {
        0 => "ACCESS_ALLOWED_ACE_TYPE || ACCESS_MIN_MS_ACE_TYPE".to_string(),
        1 => "ACCESS_DENIED_ACE_TYPE".to_string(),
        10 => "ACCESS_DENIED_CALLBACK_ACE_TYPE".to_string(),
        11 => "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE".to_string(),
        12 => "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE".to_string(),
        13 => "SYSTEM_AUDIT_CALLBACK_ACE_TYPE".to_string(),
        14 => "SYSTEM_ALARM_CALLBACK_ACE_TYPE".to_string(),
        16 => "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE".to_string(),
        21 => "ACCESS_MAX_MS_V5_ACE_TYPE".to_string(),
        2 => "SYSTEM_AUDIT_ACE_TYPE".to_string(),
        3 => "ACCESS_MAX_MS_V2_ACE_TYPE || SYSTEM_ALARM_ACE_TYPE".to_string(),
        4 => "ACCESS_MAX_MS_V3_ACE_TYPE || ACCESS_ALLOWED_COMPOUND_ACE_TYPE".to_string(),
        5 => "ACCESS_ALLOWED_OBJECT_ACE_TYPE || ACCESS_MIN_MS_OBJECT_TYPE".to_string(),
        6 => "ACCESS_DENIED_OBJECT_ACE_TYPE".to_string(),
        8 => "ACCESS_MAX_MS_V4_ACE_TYPE || ACCESS_MAX_MS_ACE_TYPE || SYSTEM_ALARM_OBJECT_ACE_TYPE"
            .to_string(),
        9 => "ACCESS_ALLOWED_CALLBACK_ACE_TYPE".to_string(),
        15 => "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE".to_string(),
        7 => "SYSTEM_AUDIT_OBJECT_ACE_TYPE".to_string(),
        17 => "SYSTEM_MANADATORY_LABEL_ACE_TYPE".to_string(),
        i => format!("Unknown {}", i).to_string(),
    }
}

#[allow(dead_code)]
fn ace_flags_to_string(ace_header: ACE_HEADER) -> String {
    let mut flags = String::new();
    if ace_header.AceFlags & CONTAINER_INHERIT_ACE.0 as u8 != 0 {
        flags.push_str("| CONTAINER_INHERIT_ACE |");
    }

    if ace_header.AceFlags & FAILED_ACCESS_ACE_FLAG.0 as u8 != 0 {
        flags.push_str("| FAILED_ACCESS_ACE_FLAG |");
    }

    if ace_header.AceFlags & INHERIT_ONLY_ACE.0 as u8 != 0 {
        flags.push_str("| INHERIT_ONLY_ACE |");
    }

    if ace_header.AceFlags & INHERITED_ACE.0 as u8 != 0 {
        flags.push_str("| INHERITED_ACE |");
    }

    if ace_header.AceFlags & NO_PROPAGATE_INHERIT_ACE.0 as u8 != 0 {
        flags.push_str("| NO_PROPAGATE_INHERIT_ACE |");
    }

    if ace_header.AceFlags & OBJECT_INHERIT_ACE.0 as u8 != 0 {
        flags.push_str("| OBJECT_INHERIT_ACE |");
    }

    if ace_header.AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG.0 as u8 != 0 {
        flags.push_str("| SUCCESSFUL_ACCESS_ACE_FLAG |");
    }

    if flags.len() != 0 {
        flags.insert_str(0, " ");
    }

    return flags;
}

#[allow(dead_code)]
/// Get all SIDs + Access Masks from an ACL
pub fn get_acl_sids(sec_desc: PSECURITY_DESCRIPTOR) -> Vec<(PSID, u32, PSTR)> {
    let mut resp: Vec<(PSID, u32, PSTR)> = Vec::new();
    unsafe {
        if sec_desc.0.is_null() {
            log::debug!("sec_desc is null");
            return Vec::new();
        }

        let ppdacl: *mut *mut ACL = std::alloc::alloc_zeroed(
            std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut ACL>(), 8),
        ) as *mut *mut ACL;
        log::debug!("GetSecurityDescriptorDacl");
        #[allow(const_item_mutation)]
        let lpdacl_present: *mut BOOL = &mut (SE_DACL_PRESENT.0) as *mut _ as *mut BOOL;
        #[allow(const_item_mutation)]
        let lpdacl_defaulted: *mut BOOL = &mut (SE_DACL_DEFAULTED.0) as *mut _ as *mut BOOL;
        let ff = GetSecurityDescriptorDacl(sec_desc, lpdacl_present, ppdacl, lpdacl_defaulted);
        log::debug!("GetSecurityDescriptorDacl {:?}", ff);
        match ff {
            Ok(_) => {}
            Err(_) => {
                log::debug!("GetSecurityDescriptorDacl failed");
                return Vec::new();
            }
        }
        log::debug!("GetSecurityDescriptorDacl done");
        log::debug!("ACL: {:?}", **ppdacl);

        let acl_size_information: *mut ACL_SIZE_INFORMATION =
            std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<ACL_SIZE_INFORMATION>(),
                8,
            )) as *mut ACL_SIZE_INFORMATION;

        let _info_resp = GetAclInformation(
            *ppdacl as *const ACL,
            acl_size_information as *mut ACL_SIZE_INFORMATION as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );
        log::debug!("GetAclInformation {:?}", _info_resp);
        log::debug!("ACE Size info: {:?}", *acl_size_information);

        let count = (**ppdacl).AceCount;

        for i in 0..count {
            let pp_ace: *mut *mut c_void =
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut c_void>(),
                    8,
                )) as *mut *mut c_void;

            log::debug!("GetAce");
            let mut _get_ace_resp = GetAce(*ppdacl, i as u32, pp_ace);
            log::debug!("GetAce {:?}", _get_ace_resp);
            let ace_header = *(*pp_ace as *const ACCESS_ALLOWED_ACE);

            match ace_header.Header.AceType as u32 {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let access_allowed_ace: ACCESS_ALLOWED_ACE =
                        *(*pp_ace as *const ACCESS_ALLOWED_ACE);
                    let sid_pstr: PSTR = PSTR(std::ptr::null_mut());
                    let psid = PSID((*pp_ace).add(8));
                    log::debug!("PSID: {:?}", psid);
                    log::debug!("SID: {:?}", *(psid.0 as *mut SID));
                    let _get_ace_sid_resp =
                        ConvertSidToStringSidA(psid, &sid_pstr as *const PSTR as *mut PSTR);
                    log::debug!("ConvertSidToStringSidA {:?}", _get_ace_sid_resp);
                    log::debug!("{:?} | SID {:?}", ace_header, sid_pstr.to_string());
                    resp.push((psid, access_allowed_ace.Mask, sid_pstr));
                }
                SYSTEM_ALARM_ACE_TYPE => {
                    let system_alarm_ace: SYSTEM_ALARM_ACE = *(*pp_ace as *const SYSTEM_ALARM_ACE);
                    let sid_pstr: PSTR = PSTR(std::ptr::null_mut());
                    let psid = PSID(&system_alarm_ace.SidStart as *const u32 as *mut c_void);
                    log::debug!("PSID: {:?}", psid);
                    log::debug!("SID: {:?}", *(psid.0 as *mut SID));
                    let _get_ace_sid_resp =
                        ConvertSidToStringSidA(psid, &sid_pstr as *const PSTR as *mut PSTR);
                    log::debug!("ConvertSidToStringSidA {:?}", _get_ace_sid_resp);
                    log::debug!("{:?} | SID {:?}", ace_header, sid_pstr.to_string());

                    resp.push((psid, system_alarm_ace.Mask, sid_pstr));
                }
                _ => {}
            };
        }
    }
    return resp;
}

fn mask_to_strings(mask: u32, out: &mut Vec<String>) {
    if mask & (GENERIC_READ.0) != 0 {
        out.push("GENERIC_READ".to_string());
    }

    if mask & (GENERIC_WRITE.0) != 0 {
        out.push("GENERIC_WRITE".to_string());
    }

    if mask & (GENERIC_EXECUTE.0) != 0 {
        out.push("GENERIC_EXECUTE".to_string());
    }

    if mask & (GENERIC_ALL.0) != 0 {
        out.push("GENERIC_ALL".to_string());
    }

    if mask & MAXIMUM_ALLOWED != 0 {
        out.push("MAXIMUM_ALLOWED".to_string());
    }

    if mask & ACCESS_SYSTEM_SECURITY != 0 {
        out.push("ACCESS_SYSTEM_SECURITY".to_string());
    }

    if mask & (SYNCHRONIZE.0) != 0 {
        out.push("SYNCHRONIZE".to_string());
    }

    if mask & (WRITE_OWNER.0) != 0 {
        out.push("WRITE_OWNER".to_string());
    }

    if mask & (WRITE_DAC.0) != 0 {
        out.push("WRITE_DAC".to_string());
    }

    if mask & (READ_CONTROL.0) != 0 {
        out.push("READ_CONTROL".to_string());
    }

    if mask & (DELETE.0) != 0 {
        out.push("DELETE".to_string());
    }

    if mask & (FILE_WRITE_ATTRIBUTES.0) != 0 {
        out.push("FILE_WRITE_ATTRIBUTES".to_string());
    }

    if mask & (FILE_READ_ATTRIBUTES.0) != 0 {
        out.push("FILE_READ_ATTRIBUTES".to_string());
    }

    if mask & (FILE_DELETE_CHILD.0) != 0 {
        out.push("FILE_DELETE_CHILD".to_string());
    }

    if mask & (FILE_EXECUTE.0) != 0 {
        out.push("FILE_EXECUTE".to_string());
    }

    if mask & (FILE_TRAVERSE.0) != 0 {
        out.push("FILE_TRAVERSE".to_string());
    }

    if mask & (FILE_WRITE_EA.0) != 0 {
        out.push("FILE_WRITE_EA".to_string());
    }

    if mask & (FILE_READ_EA.0) != 0 {
        out.push("FILE_READ_EA".to_string());
    }

    if mask & (FILE_APPEND_DATA.0) != 0 {
        out.push("FILE_APPEND_DATA".to_string());
    }

    if mask & (FILE_ADD_SUBDIRECTORY.0) != 0 {
        out.push("FILE_ADD_SUBDIRECTORY".to_string());
    }

    if mask & (FILE_CREATE_PIPE_INSTANCE.0) != 0 {
        out.push("FILE_CREATE_PIPE_INSTANCE".to_string());
    }

    if mask & (FILE_ADD_FILE.0) != 0 {
        out.push("FILE_ADD_FILE".to_string());
    }

    if mask & (FILE_WRITE_DATA.0) != 0 {
        out.push("FILE_WRITE_DATA".to_string());
    }

    if mask & (FILE_LIST_DIRECTORY.0) != 0 {
        out.push("FILE_LIST_DIRECTORY".to_string());
    }

    if mask & (FILE_READ_DATA.0) != 0 {
        out.push("FILE_READ_DATA".to_string());
    }

    return;
}

impl PartialEq for ModPathResp {
    fn eq(&self, other: &ModPathResp) -> bool {
        self.sid_str == other.sid_str && self.path == other.path && self.mask == other.mask
    }
}

impl Eq for ModPathResp {}

impl PartialOrd for ModPathResp {
    fn partial_cmp(&self, other: &ModPathResp) -> Option<std::cmp::Ordering> {
        self.sid_str
            .clone()
            .unwrap_or("".to_string())
            .partial_cmp(&other.sid_str.clone().unwrap_or("".to_string()))
    }
}

impl Ord for ModPathResp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sid_str
            .clone()
            .unwrap_or("".to_string())
            .cmp(&other.sid_str.clone().unwrap_or("".to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct ModPathResp {
    pub sid: PSID,
    pub sid_str: Result<String, FromUtf8Error>,
    pub sid_name: Result<String, FromUtf8Error>,
    pub sid_domain: Result<String, FromUtf8Error>,
    pub mask: u32,
    pub mask_strings: Vec<String>,
    pub path: String,
}

pub const WRITTABLE_PERMS: &[&str] = &[
    "GENERIC_WRITE",
    "GENERIC_ALL",
    "MAXIMUM_ALLOWED",
    "WRITE_OWNER",
    "WRITE_DAC",
    "FILE_WRITE_DATA",
    "FILE_ADD_FILE",
    "FILE_APPEND_DATA",
];

#[derive(Debug, Clone)]
pub struct SidNames {
    pub sid: PSID,
    pub sid_str: Result<String, FromUtf8Error>,
    pub sid_name: Result<String, FromUtf8Error>,
    pub sid_domain: Result<String, FromUtf8Error>,
}

pub fn get_sid_names(psid: PSID) -> SidNames {
    if psid.0.is_null() {
        return SidNames {
            sid: psid,
            sid_str: Ok("".to_owned()),
            sid_name: Ok("".to_owned()),
            sid_domain: Ok("".to_owned()),
        };
    }
    unsafe {
        let sid_pstr: PSTR = PSTR(std::ptr::null_mut());
        log::debug!("PSID: {:?}", psid);
        let _get_ace_sid_resp = ConvertSidToStringSidA(psid, &sid_pstr as *const PSTR as *mut PSTR);
        log::debug!("ConvertSidToStringSidW {:?}", _get_ace_sid_resp);
        let mut sid_name: PSTR = PSTR(std::ptr::null_mut());
        let mut sid_name_size: u32 = 0;
        let p_sid_name_size: *mut u32 = &mut sid_name_size as *mut u32;
        let mut sid_domain: PSTR = PSTR(std::ptr::null_mut());
        let mut sid_domain_size: u32 = 0;
        let p_sid_domain_size: *mut u32 = &mut sid_domain_size as *mut u32;
        let mut sid_name_use: SID_NAME_USE = SID_NAME_USE(0);
        log::debug!("in sid: {:?}", psid);
        log::debug!("in sid: {:?}", *(psid.0 as *mut SID));
        let _lookup_account_sid_resp = LookupAccountSidA(
            None,
            psid,
            sid_name,
            p_sid_name_size,
            sid_domain,
            p_sid_domain_size,
            &mut sid_name_use,
        );
        log::debug!("LookupAccountSidA {:?}", _lookup_account_sid_resp);
        log::debug!("sid_name_size {:?}", *p_sid_name_size);
        log::debug!("sid_domain_size {:?}", *p_sid_domain_size);
        let name_layout = std::alloc::Layout::from_size_align(*p_sid_name_size as usize, 8);
        log::debug!("name layout {:?}", name_layout);
        sid_name.0 = std::alloc::alloc_zeroed(name_layout.unwrap()) as *mut u8;
        let domain_layout = std::alloc::Layout::from_size_align(*p_sid_domain_size as usize, 8);
        log::debug!("domain layout {:?}", domain_layout);
        sid_domain.0 = std::alloc::alloc_zeroed(domain_layout.unwrap()) as *mut u8;
        let _lookup_account_sid_resp = LookupAccountSidA(
            None,
            psid,
            sid_name,
            p_sid_name_size,
            sid_domain,
            p_sid_domain_size,
            &mut sid_name_use,
        );
        log::debug!("LookupAccountSidA {:?}", _lookup_account_sid_resp);

        let out_name = match sid_name.0.is_null() {
            true => Ok("".to_owned()),
            false => sid_name.to_string(),
        };

        let out_domain = match sid_domain.0.is_null() {
            true => Ok("".to_owned()),
            false => sid_domain.to_string(),
        };

        SidNames {
            sid: psid,
            sid_str: sid_pstr.to_string(),
            sid_name: out_name,
            sid_domain: out_domain,
        }
    }
}

pub fn _get_modifiable_path(path: String) -> Vec<ModPathResp> {
    let mut formatted_resp: Vec<ModPathResp> = Vec::new();
    let mut unformatted_resp: Vec<(PSID, u32)> = Vec::new();
    let requested_info = DACL_SECURITY_INFORMATION;
    let mut security_descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut security_descriptor_size: u32 = 0;

    unsafe {
        let mut path_string_vec: Vec<u8> = path.clone().into_bytes();
        path_string_vec.push(0);
        log::debug!("path_string_vec: {:?}", path_string_vec);
        let pcstrr = PCSTR(path_string_vec.as_ptr() as *mut u8);
        log::debug!("GetFileSecurityA in {:?}", pcstrr.to_string());
        if pcstrr.to_string().unwrap().starts_with("\\\\") {
            return Vec::new();
        }

        let _get_file_security_resp = GetFileSecurityA(
            pcstrr,
            requested_info.0,
            security_descriptor,
            security_descriptor_size,
            &mut security_descriptor_size,
        );

        log::debug!("Security Descriptor Size: {:?}", security_descriptor_size);
        log::debug!("GetFileSecurityA out {:?}", _get_file_security_resp);

        if security_descriptor_size == 0 {
            log::debug!("Security Descriptor Size is 0");
            if is_path_writtable(path.clone()) {
                log::debug!("Path is writtable");
                let (_, _, owner, _, _) = get_token_privileges(None, None);
                let sid_strings = get_sid_names((*owner).Owner);
                let rr = ModPathResp {
                    sid: (*owner).Owner,
                    sid_str: sid_strings.sid_str,
                    sid_name: sid_strings.sid_name,
                    sid_domain: sid_strings.sid_domain,
                    mask: 0,
                    mask_strings: Vec::new(),
                    path: path.clone(),
                };
                formatted_resp.push(rr);
            }

            return formatted_resp;
        }

        security_descriptor.0 = std::alloc::alloc_zeroed(
            std::alloc::Layout::from_size_align_unchecked(security_descriptor_size as usize, 8),
        ) as *mut c_void;

        log::debug!("GetFileSecurityA in {:?}", pcstrr.to_string());
        let __get_file_security_resp = GetFileSecurityA(
            pcstrr,
            requested_info.0,
            security_descriptor,
            security_descriptor_size,
            &mut security_descriptor_size,
        );
        log::debug!("Security Descriptor Size: {:?}", security_descriptor_size);
        log::debug!("GetFileSecurityA out {:?}", __get_file_security_resp);
        log::debug!(
            "Security Descriptor: {:?}",
            *(security_descriptor.0 as *mut SECURITY_DESCRIPTOR)
        );
        let ppdacl: *mut *mut ACL = std::alloc::alloc_zeroed(
            std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut ACL>(), 8),
        ) as *mut *mut ACL;
        log::debug!("GetSecurityDescriptorDacl");
        #[allow(const_item_mutation)]
        let lpdacl_present: *mut BOOL = &mut (SE_DACL_PRESENT.0) as *mut _ as *mut BOOL;
        #[allow(const_item_mutation)]
        let lpdacl_defaulted: *mut BOOL = &mut (SE_DACL_DEFAULTED.0) as *mut _ as *mut BOOL;

        let ff = GetSecurityDescriptorDacl(
            security_descriptor,
            lpdacl_present,
            ppdacl,
            lpdacl_defaulted,
        );
        log::debug!("GetSecurityDescriptorDacl {:?}", ff);
        match ff {
            Ok(_) => {}
            Err(_) => {
                log::debug!("GetSecurityDescriptorDacl failed");
                return Vec::new();
            }
        }
        log::debug!("GetSecurityDescriptorDacl done");
        log::debug!("ACL: {:?}", **ppdacl);
        let count = (**ppdacl).AceCount;

        for i in 0..count {
            let pp_ace: *mut *mut c_void =
                std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut c_void>(),
                    8,
                )) as *mut *mut c_void;

            log::debug!("GetAce");
            let mut _get_ace_resp = GetAce(*ppdacl, i as u32, pp_ace);
            log::debug!("GetAce {:?}", _get_ace_resp);
            let ace_header = *(*pp_ace as *const ACCESS_ALLOWED_ACE);
            log::debug!("{:?}", ace_header);

            match ace_header.Header.AceType as u32 {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let access_allowed_ace: ACCESS_ALLOWED_ACE =
                        *(*pp_ace as *const ACCESS_ALLOWED_ACE);
                    let psid = PSID((*pp_ace).add(8));
                    unformatted_resp.push((psid, access_allowed_ace.Mask));
                }
                SYSTEM_ALARM_ACE_TYPE => {
                    let system_alarm_ace: SYSTEM_ALARM_ACE = *(*pp_ace as *const SYSTEM_ALARM_ACE);
                    let psid = PSID((*pp_ace).add(8));
                    unformatted_resp.push((psid, system_alarm_ace.Mask));
                }
                _ => {}
            };
        }

        for (psid, mask) in unformatted_resp {
            let mut mask_vec: Vec<String> = Vec::new();
            mask_to_strings(mask, &mut mask_vec);

            let sid_strings = get_sid_names(psid);

            let log_d = "".to_string();
            log::debug!(
                "{} - {}\\{} - {:?}",
                sid_strings.sid_str.clone().unwrap_or(log_d.clone()),
                sid_strings.sid_domain.clone().unwrap_or(log_d.clone()),
                sid_strings.sid_name.clone().unwrap_or(log_d.clone()),
                mask_vec
            );

            if !mask_vec
                .iter()
                .any(|x| WRITTABLE_PERMS.contains(&(x as &str)))
            {
                log::debug!("writtable perms not found");
                continue;
            }

            let rr = ModPathResp {
                sid: psid,
                sid_str: sid_strings.sid_str.clone(),
                sid_name: sid_strings.sid_name.clone(),
                sid_domain: sid_strings.sid_domain.clone(),
                mask: mask,
                mask_strings: mask_vec,
                path: path.clone(),
            };

            formatted_resp.push(rr);
        }
    };

    return formatted_resp;
}

/// Get all SIDs + Domain + Name + Mask Perm from path
pub fn get_modifiable_path(path: &str) -> Vec<ModPathResp> {
    let mut formatted_resp: Vec<ModPathResp> = Vec::new();
    let mut paths = Vec::new();
    let mut prev = String::new();
    let is_quoted = path.starts_with('"');
    for (i, c) in path.chars().enumerate() {
        if i == 0 && c == '"' {
            continue;
        }
        if !is_quoted && c == ' ' {
            log::debug!("prev: {:?}", prev);
            let cc = prev.clone();
            log::debug!("cc: {:?}", cc);
            paths.push(cc);

            match std::path::Path::new(&prev.clone()).try_exists() {
                Ok(true) => {
                    break;
                }
                _ => {}
            }
        }
        if is_quoted && c == '"' {
            log::debug!("prev: {:?}", prev);
            let cc = prev.clone();
            log::debug!("cc: {:?}", cc);
            paths.push(cc);
            break;
        }
        prev.push(c);
    }
    log::debug!("prev: {:?}", prev);
    let cc = prev.clone();
    log::debug!("cc: {:?}", cc);
    paths.push(cc);

    log::debug!("paths: {}", paths.len());
    for i in 0..paths.len() {
        log::debug!("paths[{}]: {:?}", i, paths[i].to_string());
    }

    for p in paths {
        log::debug!("_get_modifiable_path in path: {:?}", p);
        let resp = _get_modifiable_path(p.clone());
        log::debug!("_get_modifiable_path out path: {:?}", resp);
        formatted_resp.extend(resp);
    }

    return formatted_resp;
}

pub fn is_path_writtable(path: String) -> bool {
    log::debug!("Checking path writtable: {:?}", path);
    let path_metadata = std::fs::metadata(path.clone());

    match path_metadata {
        Ok(metadata) => {
            if metadata.permissions().readonly() {
                log::debug!("{} is readonly", path);
                return false;
            } else {
                log::debug!("{} is writtable", path);
                return true;
            }
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                log::debug!("{} not found, trying create...", path);
                match std::fs::File::create(path.clone()) {
                    Ok(_) => {
                        log::debug!("File created, {} is writtable, deleting...", path);
                        std::fs::remove_file(path).unwrap();
                        return true;
                    }
                    Err(e) => {
                        log::debug!("Error creating file {:?}: {:?}", path, e);
                        return false;
                    }
                };
            }
            _ => {
                log::debug!("Error getting metadata for {:?}: {:?}", path, e);
                return false;
            }
        },
    }
}
