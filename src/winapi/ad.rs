use crate::winapi::wmi::init_com;
use core::ffi::c_void;
use std::collections::HashMap;
use widestring::{u16cstr, Utf16String};
use windows_core::Interface;
use windows::core::{IUnknown, BSTR, HRESULT, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Networking::ActiveDirectory::{
    ADsGetObject, ADsOpenObject, IADs, IADsOpenDSObject, IDirectorySearch, ADSTYPE_BACKLINK,
    ADSTYPE_BOOLEAN, ADSTYPE_CASEIGNORE_LIST, ADSTYPE_CASE_EXACT_STRING,
    ADSTYPE_CASE_IGNORE_STRING, ADSTYPE_DN_STRING, ADSTYPE_DN_WITH_BINARY, ADSTYPE_DN_WITH_STRING,
    ADSTYPE_EMAIL, ADSTYPE_FAXNUMBER, ADSTYPE_HOLD, ADSTYPE_INTEGER, ADSTYPE_INVALID,
    ADSTYPE_LARGE_INTEGER, ADSTYPE_NETADDRESS, ADSTYPE_NT_SECURITY_DESCRIPTOR,
    ADSTYPE_NUMERIC_STRING, ADSTYPE_OBJECT_CLASS, ADSTYPE_OCTET_LIST, ADSTYPE_OCTET_STRING,
    ADSTYPE_PATH, ADSTYPE_POSTALADDRESS, ADSTYPE_PRINTABLE_STRING, ADSTYPE_PROV_SPECIFIC,
    ADSTYPE_REPLICAPOINTER, ADSTYPE_TIMESTAMP, ADSTYPE_TYPEDNAME, ADSTYPE_UNKNOWN,
    ADSTYPE_UTC_TIME, ADSVALUE, ADSVALUE_0, ADS_AUTHENTICATION_ENUM, ADS_SCOPE_SUBTREE,
    ADS_SEARCHPREF_INFO, ADS_SEARCHPREF_SEARCH_SCOPE, ADS_SEARCH_COLUMN, ADS_SEARCH_HANDLE,
    ADS_SECURE_AUTHENTICATION, ADS_STATUS_S_OK,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitialize, IDispatch, CLSCTX_ALL, CLSCTX_INPROC_SERVER,
};
use windows::Win32::System::Variant::{VariantToStringAlloc};

use core::mem::MaybeUninit;

pub fn query_users() -> Vec<HashMap<String, String>> {
    let _ = init_com();

    let root_dse = u16cstr!("LDAP://rootDSE").as_ptr();
    let obj: *mut IADs =
        unsafe { std::alloc::alloc(std::alloc::Layout::new::<IADs>()) as *mut IADs };
    let resp = unsafe {
        ADsOpenObject(
            PCWSTR(root_dse),
            None,
            None,
            ADS_SECURE_AUTHENTICATION,
            &IADs::IID,
            obj as *mut _ as *mut *mut c_void,
        )
    };
    log::debug!("ADsOpenObject succeeded {:?}", resp);

    let dn_str = BSTR::from_wide(u16cstr!("defaultNamingContext").as_slice_with_nul()).unwrap();
    let dn = unsafe { (*obj).Get(&dn_str).unwrap() };
    let dn = unsafe { VariantToStringAlloc(&dn).unwrap() };
    let dn = unsafe { dn.to_string().unwrap() };
    log::debug!("defaultNamingContext: {:?}", dn);

    let search_path = format!("LDAP://{}", dn);
    let search_path = Utf16String::from(search_path).as_ptr();
    let obj: *mut IDirectorySearch = unsafe {
        std::alloc::alloc(std::alloc::Layout::new::<IDirectorySearch>()) as *mut IDirectorySearch
    };
    for _i in 0..10 {
        let resp = unsafe {
            ADsOpenObject(
                PCWSTR(search_path),
                None,
                None,
                ADS_SECURE_AUTHENTICATION,
                &IDirectorySearch::IID,
                obj as *mut _ as *mut *mut c_void,
            )
        };
        log::debug!("ADsOpenObject succeeded {:?}", resp);
        if resp.is_ok() {
            break;
        }
    }

    //  Specify subtree search.
    let search_prefs: ADS_SEARCHPREF_INFO = ADS_SEARCHPREF_INFO {
        dwSearchPref: ADS_SEARCHPREF_SEARCH_SCOPE,
        vValue: ADSVALUE {
            dwType: ADSTYPE_INTEGER,
            Anonymous: ADSVALUE_0 {
                Integer: ADS_SCOPE_SUBTREE.0 as u32,
            },
        },
        dwStatus: ADS_STATUS_S_OK,
    };
    log::debug!("IDirectorySearch: {:?}", unsafe {
        (*obj).SetSearchPreference(&search_prefs, 1)
    });

    let filter = u16cstr!("(&(objectCategory=person)(objectClass=user))").as_ptr();
    let _p_obj: *mut IADs = std::ptr::null_mut();
    let _p_iads: *mut IADs = std::ptr::null_mut();

    let search_handle: ADS_SEARCH_HANDLE = unsafe {
        (*obj)
            .ExecuteSearch(PCWSTR(filter), std::ptr::null_mut(), (-1 as i32) as u32)
            .unwrap()
    };

    let mut resp: Vec<HashMap<String, String>> = vec![];
    loop {
        let hr = unsafe { (*obj).GetNextRow(search_handle) };
        log::debug!("GetNextRow: {:?}", hr);

        if hr == HRESULT(0x5012) {
            break;
        }

        let mut map: HashMap<String, String> = HashMap::new();
        loop {
            log::debug!("start loop");
            let column_name: *mut PWSTR = &mut PWSTR(std::ptr::null_mut());
            let column_value: *mut ADS_SEARCH_COLUMN = &mut ADS_SEARCH_COLUMN::default();

            log::debug!("GetNextColumnName");
            let hr = unsafe { (*obj).GetNextColumnName(search_handle, column_name) };
            log::debug!("GetNextColumnName: {:?}", hr);
            if hr == HRESULT(0x5013) {
                break;
            }

            let hr =
                unsafe { (*obj).GetColumn(search_handle, PCWSTR((*column_name).0), column_value) };
            log::debug!("GetColumn: {:?}", hr);

            let column_name = unsafe { (*column_name).to_string().unwrap() };
            log::debug!("column_name: {:?}", column_name);
            let column_vv = unsafe { (*column_value).pszAttrName.to_string().unwrap() };
            log::debug!("column_value: {:?}", column_vv);

            match unsafe { (*column_value).dwADsType } {
                ADSTYPE_DN_STRING => {
                    log::debug!("loading value of type ADSTYPE_DN_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { PCWSTR((*value).Anonymous.DNString).to_string().unwrap() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_CASE_EXACT_STRING => {
                    log::debug!("loading value of type ADSTYPE_DN_CASE_EXACT_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCWSTR((*value).Anonymous.CaseExactString)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_CASE_IGNORE_STRING => {
                    log::debug!("loading value of type ADSTYPE_DN_CASE_IGNORE_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCWSTR((*value).Anonymous.CaseIgnoreString)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_PRINTABLE_STRING => {
                    log::debug!("loading value of type ADSTYPE_PRINTABLE_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCWSTR((*value).Anonymous.PrintableString)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_NUMERIC_STRING => {
                    log::debug!("loading value of type ADSTYPE_NUMERIC_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCWSTR((*value).Anonymous.NumericString)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_BOOLEAN => {
                    log::debug!("loading value of type ADSTYPE_BOOLEAN");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.Boolean.to_string() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_INTEGER => {
                    log::debug!("loading value of type ADSTYPE_INTEGER");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.Integer.to_string() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_OCTET_STRING => {
                    log::debug!("loading value of type ADSTYPE_OCTET_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let mut empty: Vec<u8> = vec![];
                    unsafe {
                        for i in 0..(*value).Anonymous.OctetString.dwLength {
                            empty.push(*((*value).Anonymous.OctetString.lpValue.add(i as usize)));
                        }
                    };
                    let value = format!("value: {:?}", empty);
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_UTC_TIME => {
                    log::debug!("loading value of type ADSTYPE_UTC_TIME");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.UTCTime };
                    let value = format!(
                        "{}/{}/{} {}:{}:{}.{}",
                        value.wDay,
                        value.wMonth,
                        value.wYear,
                        value.wHour,
                        value.wMinute,
                        value.wSecond,
                        value.wMilliseconds
                    );
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_LARGE_INTEGER => {
                    log::debug!("loading value of type ADSTYPE_LARGE_INTEGER");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.LargeInteger.to_string() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_OBJECT_CLASS => {
                    log::debug!("loading value of type ADSTYPE_OBJECT_CLASS");
                    let value = unsafe { (*column_value).pADsValues };
                    let value =
                        unsafe { PCWSTR((*value).Anonymous.ClassName).to_string().unwrap() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_PROV_SPECIFIC => {
                    log::debug!("loading value of type ADSTYPE_PROV_SPECIFIC");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        String::from_raw_parts(
                            (*value).Anonymous.ProviderSpecific.lpValue,
                            (*value).Anonymous.ProviderSpecific.dwLength as usize,
                            (*value).Anonymous.ProviderSpecific.dwLength as usize,
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_CASEIGNORE_LIST => {
                    log::debug!("loading value of type ADSTYPE_CASEIGNORE_LIST");
                    let value = unsafe { (*column_value).pADsValues };
                    let mut merged: String = String::new();
                    if unsafe { (*value).Anonymous.pCaseIgnoreList.is_null() } {
                        break;
                    }
                    let value = unsafe { (*value).Anonymous.pCaseIgnoreList };
                    loop {
                        unsafe { merged.push_str(&((*value).String.to_string().unwrap())) };

                        let value = unsafe { (*value).Next };
                        if value.is_null() {
                            break;
                        }
                    }
                    log::debug!("value: {:?}", merged);
                    map.insert(column_name, merged);
                }
                ADSTYPE_OCTET_LIST => {
                    log::debug!("loading value of type ADSTYPE_OCTET_LIST");
                    let value = unsafe { (*column_value).pADsValues };
                    let mut merged: String = String::new();
                    if unsafe { (*value).Anonymous.pCaseIgnoreList.is_null() } {
                        break;
                    }
                    let value = unsafe { (*value).Anonymous.pOctetList };
                    loop {
                        unsafe {
                            merged.push_str(
                                &(String::from_raw_parts(
                                    (*value).Data,
                                    (*value).Length as usize,
                                    (*value).Length as usize,
                                )),
                            )
                        };
                        let value = unsafe { (*value).Next };
                        if value.is_null() {
                            break;
                        }
                    }
                    log::debug!("value: {:?}", merged);
                    map.insert(column_name, merged);
                }
                ADSTYPE_PATH => {
                    log::debug!("loading value of type ADSTYPE_PATH");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.pPath };
                    let value = unsafe {
                        format!(
                            "{}/{}",
                            (*value).VolumeName.to_string().unwrap(),
                            (*value).Path.to_string().unwrap()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_POSTALADDRESS => {
                    log::debug!("loading value of type ADSTYPE_POSTALADDRESS");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.pPostalAddress };
                    let value = unsafe {
                        format!(
                            "{}/{}/{}/{}/{}/{}",
                            (*value).PostalAddress[0].to_string().unwrap(),
                            (*value).PostalAddress[1].to_string().unwrap(),
                            (*value).PostalAddress[2].to_string().unwrap(),
                            (*value).PostalAddress[3].to_string().unwrap(),
                            (*value).PostalAddress[4].to_string().unwrap(),
                            (*value).PostalAddress[5].to_string().unwrap()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_TIMESTAMP => {
                    log::debug!("loading value of type ADSTYPE_TIMESTAMP");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.Timestamp };
                    let value = format!("{} {}", value.WholeSeconds, value.EventID);
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_BACKLINK => {
                    log::debug!("loading value of type ADSTYPE_BACKLINK");
                    let value = unsafe { (*column_value).pADsValues };
                    let value =
                        unsafe { (*value).Anonymous.BackLink.ObjectName.to_string().unwrap() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_TYPEDNAME => {
                    log::debug!("loading value of type ADSTYPE_TYPEDNAME");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.pTypedName };
                    let value = unsafe {
                        format!(
                            "{}/{}/{}",
                            (*value).Level.to_string(),
                            (*value).ObjectName.to_string().unwrap(),
                            (*value).Interval.to_string()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_HOLD => {
                    log::debug!("loading value of type ADSTYPE_HOLD");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.Hold.ObjectName.to_string().unwrap() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_NETADDRESS => {
                    log::debug!("loading value of type ADSTYPE_NETADDRESS");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCSTR((*(*value).Anonymous.pNetAddress).Address)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_REPLICAPOINTER => {
                    log::debug!("loading value of type ADSTYPE_REPLICAPOINTER");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.pReplicaPointer };
                    let value = unsafe {
                        format!(
                            "{}/{}/{}/{}",
                            (*value).ServerName.to_string().unwrap(),
                            PCSTR((*(*value).ReplicaAddressHints).Address)
                                .to_string()
                                .unwrap(),
                            (*value).ReplicaNumber.to_string(),
                            (*value).Count.to_string()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_FAXNUMBER => {
                    log::debug!("loading value of type ADSTYPE_FAXNUMBER");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.pFaxNumber };
                    let value = unsafe {
                        format!(
                            "{}/{}/{}",
                            (*value).TelephoneNumber.to_string().unwrap(),
                            (*value).NumberOfBits.to_string(),
                            PCSTR((*value).Parameters).to_string().unwrap()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_EMAIL => {
                    log::debug!("loading value of type ADSTYPE_EMAIL");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe { (*value).Anonymous.Email.Address.to_string().unwrap() };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_NT_SECURITY_DESCRIPTOR => {
                    log::debug!("loading value of type ADSTYPE_NT_SECURITY_DESCRIPTOR");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        PCSTR((*value).Anonymous.SecurityDescriptor.lpValue)
                            .to_string()
                            .unwrap()
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_DN_WITH_BINARY => {
                    log::debug!("loading value of type ADSTYPE_DN_WITH_BINARY");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        format!(
                            "{}(+binary)",
                            (*(*value).Anonymous.pDNWithBinary)
                                .pszDNString
                                .to_string()
                                .unwrap()
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                ADSTYPE_DN_WITH_STRING => {
                    log::debug!("loading value of type ADSTYPE_DN_WITH_STRING");
                    let value = unsafe { (*column_value).pADsValues };
                    let value = unsafe {
                        format!(
                            "{}/{}",
                            (*(*value).Anonymous.pDNWithString)
                                .pszDNString
                                .to_string()
                                .unwrap(),
                            (*(*value).Anonymous.pDNWithString)
                                .pszStringValue
                                .to_string()
                                .unwrap(),
                        )
                    };
                    log::debug!("value: {:?}", value);
                    map.insert(column_name, value);
                }
                val => {
                    log::debug!("loading value of type {:?}", val);
                    log::debug!("value: {:?}", unsafe { (*column_value).pADsValues });
                    map.insert(column_name, format!("unknown type: {:?}", val));
                }
            }
        }
        resp.push(map);
    }

    resp
}
