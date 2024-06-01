use windows::core::{BSTR, PCWSTR, VARIANT};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VariantToStringAlloc};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
};

pub fn get_field(p: &IWbemClassObject, name_str: &str) -> String {
    unsafe {
        let bname =
            BSTR::from_wide(name_str.encode_utf16().collect::<Vec<u16>>().as_slice()).unwrap();
        let name = PCWSTR::from_raw((bname.as_wide()).as_ptr() as *const u16);
        let mut value: VARIANT  = std::mem::zeroed();
        let _get_resp = p.Get(name, 0, (&mut value) as *mut _ as *mut VARIANT, None, None);
        VariantToStringAlloc(&value).unwrap().to_string().unwrap()
    }
}

thread_local! {
    pub static WMI: IWbemServices = init_wmi().unwrap();
}

pub fn init_com() -> Result<(), String> {
    unsafe {
        match CoInitializeEx(None, COINIT_MULTITHREADED).ok() {
            Ok(_) => log::info!("CoInitializeEx Success"),
            Err(e) => {
                let err = format!("CoInitializeEx Error {:?}", e);
                log::error!("{}", err);
                return Err(err);
            }
        };

        match CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        ) {
            Ok(_) => log::info!("CoInitializeSecurity Success"),
            Err(e) => {
                let err = format!("CoInitializeSecurity Error {:?}", e);
                log::error!("{}", err);
                return Err(err);
            }
        };
    }
    Ok(())
}

/// Initialize WMI, run once per thread
pub fn init_wmi() -> Result<IWbemServices, String> {
    unsafe {
        let p_loc: IWbemLocator = match CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) {
            Ok(p) => p,
            Err(e) => {
                let err = format!("CoCreateInstance Error {:?}", e);
                log::error!("{}", err);
                let _ = init_com();
                CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).unwrap()
            }
        };

        let p_svc: IWbemServices = match p_loc.ConnectServer(
            &BSTR::from("ROOT\\CIMV2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &BSTR::new(),
            None,
        ) {
            Ok(p) => p,
            Err(e) => {
                let err = format!("ConnectServer Error {:?}", e);
                log::error!("{}", err);
                return Err(err);
            }
        };

        log::info!("Connected to ROOT\\CIMV2 WMI namespace");

        match CoSetProxyBlanket(
            &p_svc,
            RPC_C_AUTHN_DEFAULT as u32,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        ) {
            Ok(_) => log::info!("CoSetProxyBlanket Success"),
            Err(e) => {
                let err = format!("CoSetProxyBlanket Error {:?}", e);
                log::error!("{}", err);
                return Err(err);
            }
        };

        return Ok(p_svc);
    }
}
