use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use windows::core::{BSTR, HRESULT, PSTR};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::Security::Authorization::ConvertSidToStringSidA;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidA, TokenUser, SID_NAME_USE, TOKEN_INFORMATION_CLASS,
    TOKEN_QUERY, TOKEN_QUERY_SOURCE, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPALL,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, EnumProcessModulesEx, GetModuleBaseNameA, GetModuleFileNameExA,
    GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::System::Wmi::{
    WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WBEM_S_FALSE,
};

use crate::winapi::token::get_token_info;
use crate::winapi::wmi::{get_field, WMI};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct _Process {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: u32,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: String,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Process {
    pub creation_class_name: String,
    pub caption: String,
    pub command_line: String,
    pub creation_date: String,
    pub cs_creation_class_name: String,
    pub cs_name: String,
    pub description: String,
    pub executable_path: String,
    pub execution_state: String,
    pub handle: String,
    pub handle_count: String,
    pub install_date: String,
    pub kernel_mode_time: String,
    pub maximum_working_set_size: String,
    pub minimum_working_set_size: String,
    pub name: String,
    pub os_creation_class_name: String,
    pub os_name: String,
    pub other_operation_count: String,
    pub other_transfer_count: String,
    pub page_faults: String,
    pub page_file_usage: String,
    pub parent_process_id: String,
    pub peak_page_file_usage: String,
    pub peak_virtual_size: String,
    pub peak_working_set_size: String,
    pub priority: String,
    pub private_page_count: String,
    pub process_id: String,
    pub quota_non_paged_pool_usage: String,
    pub quota_paged_pool_usage: String,
    pub quota_peak_non_paged_pool_usage: String,
    pub quota_peak_paged_pool_usage: String,
    pub read_operation_count: String,
    pub read_transfer_count: String,
    pub session_id: String,
    pub status: String,
    pub termination_date: String,
    pub thread_count: String,
    pub user_mode_time: String,
    pub virtual_size: String,
    pub windows_version: String,
    pub working_set_size: String,
    pub write_operation_count: String,
    pub write_transfer_count: String,
    pub owner_user: String,
    pub owner_domain: String,
    pub module_info: Vec<ProcessModule>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ProcessModule {
    pub file_name: String,
    pub base_address: String,
    pub size_of_image: String,
    pub entry_point: String,
}

pub fn load_process_modules(ph: HANDLE) -> Vec<ProcessModule> {
    let mut modules = Vec::new();
    let mut h_modules: Vec<HMODULE> = vec![HMODULE(0)];
    let mut cb_needed: u32 = 0;
    let resp = unsafe {
        EnumProcessModules(
            ph,
            h_modules.as_mut_ptr(),
            std::mem::size_of::<HMODULE>() as u32,
            &mut cb_needed,
        )
    };
    log::debug!("EnumProcessModulesEx: {:?}", resp);
    if resp.is_err() {
        log::error!("Failed to enumerate process modules");
        return modules;
    }

    let module_count = cb_needed / std::mem::size_of::<HMODULE>() as u32;
    h_modules.resize(module_count as usize, HMODULE(0));
    log::debug!("Found {} modules", module_count);
    let resp = unsafe { EnumProcessModules(ph, h_modules.as_mut_ptr(), cb_needed, &mut cb_needed) };
    log::debug!("Found {} modules", module_count);
    if resp.is_err() {
        log::error!("Failed to enumerate process modules");
        return modules;
    }

    for h_module in h_modules {
        let mut module_info = [0u8; 1024];
        let resp = unsafe { GetModuleFileNameExA(ph, h_module, &mut module_info) };
        log::debug!("GetModuleFileNameExA: {:?}", resp);
        if resp == 0 {
            log::error!("Failed to get module file name");
            continue;
        }

        let file_name = String::from_utf8_lossy(&module_info)
            .to_string()
            .trim_matches(char::from(0))
            .to_string();
        let mut module_info = [0u8; 1024];
        let resp = unsafe {
            GetModuleInformation(
                ph,
                h_module,
                module_info.as_mut_ptr() as *mut MODULEINFO,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };
        log::debug!("GetModuleInformation: {:?}", resp);
        if resp.is_err() {
            log::error!("Failed to get module information");
            continue;
        }
        let module_info = unsafe { module_info.as_ptr().cast::<MODULEINFO>().read() };
        let base_address = format!("{:?}", module_info.lpBaseOfDll);
        let size_of_image = format!("{:?}", module_info.SizeOfImage);
        let entry_point = format!("{:?}", module_info.EntryPoint);

        let module = ProcessModule {
            file_name,
            base_address,
            size_of_image,
            entry_point,
        };
        modules.push(module);
    }

    log::debug!("Found {:?} modules", modules);
    modules
}

pub fn load_processes() -> Vec<Process> {
    unsafe {
        let query = BSTR::from("SELECT * FROM Win32_Process");
        let query_lang = BSTR::from("WQL");

        let p_enumerator = match WMI.with(|p_svc| {
            match p_svc.ExecQuery(
                &query_lang,
                &query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            ) {
                Ok(p_enumerator) => Some(p_enumerator),
                Err(e) => {
                    log::error!("Failed to get WMI enumerator: {}", e);
                    None
                }
            }
        }) {
            Some(p_enumerator) => p_enumerator,
            None => {
                return Vec::new();
            }
        };

        let mut objs = [None];
        let mut obj_count = 0;
        let mut hres = HRESULT(0);
        let mut processes = Vec::new();
        while hres.0 != WBEM_S_FALSE.0 {
            log::debug!("loading Next");
            hres = p_enumerator.Next(WBEM_INFINITE, &mut objs, &mut obj_count);
            log::debug!("Next: {:?}", hres);
            match &objs[0] {
                Some(obj) => {
                    let creation_class_name = get_field(obj, "CreationClassName");
                    let caption = get_field(obj, "Caption");
                    let command_line = get_field(obj, "CommandLine");
                    let creation_date = get_field(obj, "CreationDate");
                    let cs_creation_class_name = get_field(obj, "CSCreationClassName");
                    let cs_name = get_field(obj, "CSName");
                    let description = get_field(obj, "Description");
                    let executable_path = get_field(obj, "ExecutablePath");
                    let execution_state = get_field(obj, "ExecutionState");
                    let handle = get_field(obj, "Handle");
                    let handle_count = get_field(obj, "HandleCount");
                    let install_date = get_field(obj, "InstallDate");
                    let kernel_mode_time = get_field(obj, "KernelModeTime");
                    let maximum_working_set_size = get_field(obj, "MaximumWorkingSetSize");
                    let minimum_working_set_size = get_field(obj, "MinimumWorkingSetSize");
                    let name = get_field(obj, "Name");
                    let os_creation_class_name = get_field(obj, "OSCreationClassName");
                    let os_name = get_field(obj, "OSName");
                    let other_operation_count = get_field(obj, "OtherOperationCount");
                    let other_transfer_count = get_field(obj, "OtherTransferCount");
                    let page_faults = get_field(obj, "PageFaults");
                    let page_file_usage = get_field(obj, "PageFileUsage");
                    let parent_process_id = get_field(obj, "ParentProcessId");
                    let peak_page_file_usage = get_field(obj, "PeakPageFileUsage");
                    let peak_virtual_size = get_field(obj, "PeakVirtualSize");
                    let peak_working_set_size = get_field(obj, "PeakWorkingSetSize");
                    let priority = get_field(obj, "Priority");
                    let private_page_count = get_field(obj, "PrivatePageCount");
                    let _process_id = get_field(obj, "ProcessId");
                    let quota_non_paged_pool_usage = get_field(obj, "QuotaNonPagedPoolUsage");
                    let quota_paged_pool_usage = get_field(obj, "QuotaPagedPoolUsage");
                    let quota_peak_non_paged_pool_usage =
                        get_field(obj, "QuotaPeakNonPagedPoolUsage");
                    let quota_peak_paged_pool_usage = get_field(obj, "QuotaPeakPagedPoolUsage");
                    let read_operation_count = get_field(obj, "ReadOperationCount");
                    let read_transfer_count = get_field(obj, "ReadTransferCount");
                    let session_id = get_field(obj, "SessionId");
                    let status = get_field(obj, "Status");
                    let termination_date = get_field(obj, "TerminationDate");
                    let thread_count = get_field(obj, "ThreadCount");
                    let user_mode_time = get_field(obj, "UserModeTime");
                    let virtual_size = get_field(obj, "VirtualSize");
                    let windows_version = get_field(obj, "WindowsVersion");
                    let working_set_size = get_field(obj, "WorkingSetSize");
                    let write_operation_count = get_field(obj, "WriteOperationCount");
                    let write_transfer_count = get_field(obj, "WriteTransferCount");

                    log::debug!("Found process: {}", obj.GetObjectText(0).unwrap());

                    let process_id: u32 = handle.parse().unwrap();
                    let process_access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
                    let process_inherit_handle: bool = false;

                    let process_handle =
                        OpenProcess(process_access, process_inherit_handle, process_id);

                    let mut module_info = Vec::new();
                    let mut owner_user = String::new();
                    let mut owner_domain = String::new();

                    match process_handle {
                        Err(e) => {
                            log::debug!("Failed to open process: {}", e);
                        }
                        Ok(ph) => {
                            log::debug!("Opened process: {:?}", ph);

                            module_info = load_process_modules(ph);

                            let tk_h: *mut HANDLE = &mut HANDLE(0);
                            let resp = OpenProcessToken(ph, TOKEN_QUERY | TOKEN_QUERY_SOURCE, tk_h);
                            log::debug!("OpenProcessToken: {:?}", resp);

                            let domain = PSTR([0u8; 1024].as_mut_ptr());
                            let mut domain_size = 1024u32;
                            let user = PSTR([0u8; 1024].as_mut_ptr());
                            let mut user_size = 1024u32;
                            let pe_use: *mut SID_NAME_USE = &mut SID_NAME_USE(0);

                            log::debug!("GetTokenInformation: {:?}", tk_h);
                            let mut token_info_size = 0u32;
                            let token_user_info: *mut TOKEN_USER;
                            let resp = GetTokenInformation(
                                *tk_h,
                                TokenUser,
                                None,
                                token_info_size,
                                &mut token_info_size,
                            );
                            log::debug!("GetTokenInformation: {:?}", resp);
                            log::debug!("GetTokenInformation: {:?}", token_info_size);
                            token_user_info =
                                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                    token_info_size as usize,
                                    8,
                                )) as *mut TOKEN_USER;
                            let resp = GetTokenInformation(
                                *tk_h,
                                TokenUser,
                                Some(token_user_info as *mut c_void),
                                token_info_size,
                                &mut token_info_size,
                            );
                            log::debug!("GetTokenInformation: {:?}", resp);
                            log::debug!("GetTokenInformation: {:?}", token_user_info);
                            if resp.is_ok() {
                                log::debug!("LookupAccountSidA: {:?}", token_user_info);
                                log::debug!("LookupAccountSidA: {:?}", (*token_user_info).User.Sid);
                                let res = LookupAccountSidA(
                                    None,
                                    (*token_user_info).User.Sid,
                                    user,
                                    &mut user_size,
                                    domain,
                                    &mut domain_size,
                                    pe_use,
                                );
                                log::debug!("LookupAccountSidA: {:?}", res);
                                if res.is_ok() {
                                    log::debug!("user: {:?}", user.as_bytes());
                                    owner_user =
                                        String::from_utf8_lossy(user.as_bytes()).to_string();
                                    log::debug!("owner_user: {:?}", owner_user);
                                    log::debug!("domain: {:?}", domain.as_bytes());
                                    owner_domain =
                                        String::from_utf8_lossy(domain.as_bytes()).to_string();
                                    log::debug!("owner_domain: {:?}", owner_domain);
                                }
                            }
                        }
                    }

                    log::debug!("making process");
                    let process = Process {
                        creation_class_name,
                        caption,
                        command_line,
                        creation_date,
                        cs_creation_class_name,
                        cs_name,
                        description,
                        executable_path,
                        execution_state,
                        handle,
                        handle_count,
                        install_date,
                        kernel_mode_time,
                        maximum_working_set_size,
                        minimum_working_set_size,
                        name,
                        os_creation_class_name,
                        os_name,
                        other_operation_count,
                        other_transfer_count,
                        page_faults,
                        page_file_usage,
                        parent_process_id,
                        peak_page_file_usage,
                        peak_virtual_size,
                        peak_working_set_size,
                        priority,
                        private_page_count,
                        process_id: process_id.clone().to_string(),
                        quota_non_paged_pool_usage,
                        quota_paged_pool_usage,
                        quota_peak_non_paged_pool_usage,
                        quota_peak_paged_pool_usage,
                        read_operation_count,
                        read_transfer_count,
                        session_id,
                        status,
                        termination_date,
                        thread_count,
                        user_mode_time,
                        virtual_size,
                        windows_version,
                        working_set_size,
                        write_operation_count,
                        write_transfer_count,
                        owner_user: owner_user,
                        owner_domain: owner_domain,
                        module_info: module_info,
                    };

                    log::debug!("Found process: {:?}", process);
                    processes.push(process);
                    log::debug!("done pushing process");
                }
                None => {
                    log::error!("Failed to get process object");
                    break;
                }
            }

            log::debug!("hres: {:?}", hres);
            log::debug!("WBEM_S_FALSE: {:?}", WBEM_S_FALSE);
            if hres.0 == WBEM_S_FALSE.0 {
                log::debug!("hres == WBEM_S_FALSE");
                let _ = p_enumerator.Reset();
                break;
            }

            log::debug!("loading next object");
        }
        processes
    }
}
