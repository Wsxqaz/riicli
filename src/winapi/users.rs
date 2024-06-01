use windows::core::PWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED};

use windows::Win32::NetworkManagement::NetManagement::{
    NERR_GroupExists, NERR_InvalidComputer, NERR_NotPrimary, NERR_PasswordTooShort, NERR_Success,
    NERR_UserExists, NetUserAdd, UF_SCRIPT, USER_ACCOUNT_FLAGS, USER_INFO_1, USER_PRIV,
    USER_PRIV_USER,
};

#[allow(non_upper_case_globals)]
#[allow(unreachable_patterns)]
fn code_to_string(i: u32) -> String {
    let _err_access_denied: u32 = ERROR_ACCESS_DENIED.0;

    match i {
        NERR_Success => "NERR_Success".to_owned(),
        NERR_InvalidComputer => "NERR_InvalidComputer".to_owned(),
        NERR_NotPrimary => "NERR_NotPrimary".to_owned(),
        NERR_GroupExists => "NERR_GroupExists".to_owned(),
        NERR_UserExists => "NERR_UserExists".to_owned(),
        NERR_PasswordTooShort => "NERR_PasswordTooShort".to_owned(),
        _err_access_denied => "ERROR_ACCESS_DENIED".to_owned(),
        _ => format!("Unknown error code: {}", i),
    }
}

/// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
#[allow(dead_code)]
pub async fn create_user() -> () {
    let user_string: String = "john".to_owned();
    let mut user_vec: Vec<u16> = user_string.clone().encode_utf16().collect::<Vec<u16>>();
    user_vec.push(0);
    let user: PWSTR = PWSTR(user_vec.as_ptr() as *mut u16);
    let password_string: String = "##WasWord123!".to_owned();
    let mut password_vec: Vec<u16> = password_string.clone().encode_utf16().collect::<Vec<u16>>();
    password_vec.push(0);
    let password: PWSTR = PWSTR(password_vec.as_ptr() as *mut u16);
    let password_age = 0;
    let priv_level: USER_PRIV = USER_PRIV_USER;
    let home_dir_string: String = "C:\\Users\\john".to_owned();
    let mut home_dir_vec: Vec<u16> = home_dir_string.clone().encode_utf16().collect::<Vec<u16>>();
    home_dir_vec.push(0);
    let home_dir: PWSTR = PWSTR(home_dir_vec.as_ptr() as *mut u16);
    std::fs::create_dir_all(home_dir_string.clone()).unwrap();
    let comment_string: String = "John Doe".to_owned();
    let mut comment_vec: Vec<u16> = comment_string.clone().encode_utf16().collect::<Vec<u16>>();
    comment_vec.push(0);
    let comment: PWSTR = PWSTR(comment_vec.as_ptr() as *mut u16);
    let flags: USER_ACCOUNT_FLAGS = USER_ACCOUNT_FLAGS(UF_SCRIPT.0);
    let script_path: PWSTR = PWSTR(std::ptr::null_mut());
    let user_info = USER_INFO_1 {
        usri1_name: user,
        usri1_password: password,
        usri1_password_age: password_age,
        usri1_priv: priv_level,
        usri1_home_dir: home_dir,
        usri1_comment: comment,
        usri1_flags: flags,
        usri1_script_path: script_path,
    };
    let buffer = &user_info as *const _ as *const u8;
    let user_info_level = 1;
    let mut error = 0;

    unsafe {
        log::info!("create_user: {}", user_string);
        let resp = NetUserAdd(None, user_info_level, buffer, Some(&mut error));
        log::info!("create_user resp: {:?}", code_to_string(resp));
        log::info!("create_user error: {:?}", error);
        log::info!("create_user error: {:?}", GetLastError());
    }
}
