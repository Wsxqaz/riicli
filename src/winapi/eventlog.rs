use crate::utils::expand_env_strings;
use crate::winapi::acl::get_sid_names;
use crate::winapi::registry::{read_reg_key, RegKey};
use roxmltree::{Document, Node};
use std::collections::HashMap;
use std::ffi::c_void;
use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HMODULE, PSID};
use windows::Win32::System::EventLog::{
    EvtNext, EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtRender, EvtRenderEventXml, OpenEventLogA, ReadEventLogA, EVENTLOGRECORD,
    EVENTLOG_SEQUENTIAL_READ, EVT_HANDLE, READ_EVENT_LOG_READ_FLAGS,
};
use windows::Win32::System::LibraryLoader::{
    LoadLibraryExA, LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_FLAGS,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::SystemServices::EVENTLOG_BACKWARDS_READ;

#[derive(Debug, Clone, Default)]
pub struct EventLogGeneric {
    pub json: HashMap<String, String>,
}

impl From<String> for EventLogGeneric {
    fn from(value: String) -> Self {
        let doc = Document::parse(&value);
        if doc.is_err() {
            return EventLogGeneric::default();
        }
        let doc = doc.unwrap();
        let doc = doc.descendants().find(|n| n.has_tag_name("Event")).unwrap();
        let doc = doc
            .descendants()
            .find(|n| n.has_tag_name("EventData"))
            .unwrap();

        let mut json = HashMap::new();
        for child in doc.children() {
            let name = child.attribute("Name").unwrap_or("");
            let value = child.text().unwrap_or("");
            json.insert(name.to_string(), value.to_string());
        }

        let ev = EventLogGeneric { json };
        log::debug!("EventLogGeneric: {:?}", ev);
        ev
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventLogLogon {
    pub subject_user_sid: String,
    pub subject_user_name: String,
    pub subject_domain_name: String,
    pub subject_logon_id: String,
    pub target_user_sid: String,
    pub target_user_name: String,
    pub target_domain_name: String,
    pub target_logon_id: String,
    pub target_server_name: String,
    pub target_info: String,
    pub logon_type: String,
    pub logon_process_name: String,
    pub authentication_package_name: String,
    pub workstation_name: String,
    pub logon_guid: String,
    pub transmitted_services: String,
    pub lmpackage_name: String,
    pub key_length: String,
    pub process_id: String,
    pub process_name: String,
    pub ip_address: String,
    pub ip_port: String,
    pub impersontation_level: String,
    pub restricted_admin_mode: String,
    pub target_outbound_user_name: String,
    pub target_outbound_domain_name: String,
    pub virtual_account: String,
    pub target_linked_logon_id: String,
    pub elevated_token: String,
}

fn find_event_data(doc: &Node, name: &str) -> String {
    doc.descendants()
        .find(|n| n.attribute("Name") == Some(name))
        .map(|n| n.text().unwrap_or(""))
        .unwrap_or("")
        .to_string()
}

fn find_tag_name(doc: &Node, name: &str, attribute: Option<&str>) -> String {
    let tag = doc.descendants().find(|n| n.has_tag_name(name));

    match attribute {
        None => tag.map(|n| n.text().unwrap_or("")),
        Some(attr) => tag.map(|n| n.attribute(attr).unwrap_or("")),
    }
    .unwrap_or("")
    .to_string()
}

impl From<String> for EventLogLogon {
    fn from(value: String) -> Self {
        let doc = Document::parse(&value);
        if doc.is_err() {
            return EventLogLogon::default();
        }
        let doc = doc.unwrap();
        let doc = doc.descendants().find(|n| n.has_tag_name("Event")).unwrap();
        let doc = doc
            .descendants()
            .find(|n| n.has_tag_name("EventData"))
            .unwrap();
        let subject_user_sid = find_event_data(&doc, "SubjectUserSid");
        let subject_user_name = find_event_data(&doc, "SubjectUserName");
        let subject_domain_name = find_event_data(&doc, "SubjectDomainName");
        let subject_logon_id = find_event_data(&doc, "SubjectLogonId");
        let target_user_sid = find_event_data(&doc, "TargetUserSid");
        let target_user_name = find_event_data(&doc, "TargetUserName");
        let target_domain_name = find_event_data(&doc, "TargetDomainName");
        let target_logon_id = find_event_data(&doc, "TargetLogonId");
        let target_server_name = find_event_data(&doc, "TargetServerName");
        let target_info = find_event_data(&doc, "TargetInfo");
        let logon_type = find_event_data(&doc, "LogonType");
        let logon_process_name = find_event_data(&doc, "LogonProcessName");
        let authentication_package_name = find_event_data(&doc, "AuthenticationPackageName");
        let workstation_name = find_event_data(&doc, "WorkstationName");
        let logon_guid = find_event_data(&doc, "LogonGuid");
        let transmitted_services = find_event_data(&doc, "TransmittedServices");
        let lmpackage_name = find_event_data(&doc, "LmPackageName");
        let key_length = find_event_data(&doc, "KeyLength");
        let process_id = find_event_data(&doc, "ProcessId");
        let process_name = find_event_data(&doc, "ProcessName");
        let ip_address = find_event_data(&doc, "IpAddress");
        let ip_port = find_event_data(&doc, "IpPort");
        let impersontation_level = find_event_data(&doc, "ImpersonationLevel");
        let restricted_admin_mode = find_event_data(&doc, "RestrictedAdminMode");
        let target_outbound_user_name = find_event_data(&doc, "TargetOutboundUserName");
        let target_outbound_domain_name = find_event_data(&doc, "TargetOutboundDomainName");
        let virtual_account = find_event_data(&doc, "VirtualAccount");
        let target_linked_logon_id = find_event_data(&doc, "TargetLinkedLogonId");
        let elevated_token = find_event_data(&doc, "ElevatedToken");

        let ev = EventLogLogon {
            subject_user_sid,
            subject_user_name,
            subject_domain_name,
            subject_logon_id,
            target_user_sid,
            target_user_name,
            target_domain_name,
            target_logon_id,
            target_server_name,
            target_info,
            logon_type,
            logon_process_name,
            authentication_package_name,
            workstation_name,
            logon_guid,
            transmitted_services,
            lmpackage_name,
            key_length,
            process_id,
            process_name,
            ip_address,
            ip_port,
            impersontation_level,
            restricted_admin_mode,
            target_outbound_user_name,
            target_outbound_domain_name,
            virtual_account,
            target_linked_logon_id,
            elevated_token,
        };
        log::debug!("EventLogLogon: {:?}", ev);
        ev
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventLogMetadata {
    provider_name: String,
    provider_guid: String,
    event_id: String,
    version: String,
    level: String,
    task: String,
    opcode: String,
    keywords: String,
    time_created: String,
    event_record_id: String,
    activity_id: String,
    process_id: String,
    thread_id: String,
    channel: String,
    computer: String,
}

impl From<String> for EventLogMetadata {
    fn from(value: String) -> Self {
        let doc = Document::parse(&value);
        if doc.is_err() {
            return EventLogMetadata::default();
        }
        let doc = doc.unwrap();
        let doc = doc
            .descendants()
            .find(|n| n.has_tag_name("System"))
            .unwrap();
        let provider_name = find_tag_name(&doc, "Provider", Some("Name"));
        let provider_guid = find_tag_name(&doc, "Provider", Some("Guid"));
        let event_id = find_tag_name(&doc, "EventID", None);
        let version = find_tag_name(&doc, "Version", None);
        let level = find_tag_name(&doc, "Level", None);
        let task = find_tag_name(&doc, "Task", None);
        let opcode = find_tag_name(&doc, "Opcode", None);
        let keywords = find_tag_name(&doc, "Keywords", None);
        let time_created = find_tag_name(&doc, "TimeCreated", Some("SystemTime"));
        let event_record_id = find_tag_name(&doc, "EventRecordID", None);
        let activity_id = find_tag_name(&doc, "Correlation", Some("ActivityID"));
        let process_id = find_tag_name(&doc, "Execution", Some("ProcessID"));
        let thread_id = find_tag_name(&doc, "Execution", Some("ThreadID"));
        let channel = find_tag_name(&doc, "Channel", None);
        let computer = find_tag_name(&doc, "Computer", None);

        let ev = EventLogMetadata {
            provider_name,
            provider_guid,
            event_id,
            version,
            level,
            task,
            opcode,
            keywords,
            time_created,
            event_record_id,
            activity_id,
            process_id,
            thread_id,
            channel,
            computer,
        };
        log::debug!("EventLogMetadata: {:?}", ev);
        ev
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventLogRecord<T: From<String>> {
    metadata: EventLogMetadata,
    event: T,
}

pub fn read_eventlog<T: From<String>>(log_name: String, query: String) -> Vec<EventLogRecord<T>> {
    let mut events: Vec<EventLogRecord<T>> = Vec::new();
    let mut path_vec = log_name.encode_utf16().collect::<Vec<u16>>();
    path_vec.push(0);
    let path_pcwstr = PCWSTR::from_raw(path_vec.as_ptr() as *const u16);

    let mut query_vec = query.encode_utf16().collect::<Vec<u16>>();
    query_vec.push(0);
    let query_pcwstr = PCWSTR::from_raw(query_vec.as_ptr() as *const u16);

    let ev_handle: EVT_HANDLE = unsafe {
        EvtQuery(
            None,
            path_pcwstr,
            query_pcwstr,
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
        .unwrap()
    };
    log::debug!("Eventlog handle: {:?}", ev_handle);

    let mut out_handles: Vec<isize> = vec![0; 1000];
    let mut num_handles = 0;
    let resp = unsafe {
        EvtNext(
            ev_handle,
            out_handles.as_mut_slice(),
            1000,
            0,
            &mut num_handles,
        )
    };
    log::debug!("EvtNext: {:?}", resp);
    log::debug!("Num handles: {:?}", num_handles);

    for handle in out_handles[..num_handles as usize].iter() {
        let mut buffer = vec![0; 1024 * 64];
        let buffer_size = buffer.len() as u32;
        let mut buffer_used = 0;
        let mut property_count = 0;
        let resp = unsafe {
            EvtRender(
                None,
                EVT_HANDLE(*handle),
                EvtRenderEventXml.0,
                buffer_size,
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut buffer_used,
                &mut property_count,
            )
        };

        let xml_string = String::from_utf16_lossy(&buffer[0..buffer_used as usize]);
        let xml_string = xml_string.trim_end_matches('\u{0}');
        events.push(EventLogRecord {
            metadata: EventLogMetadata::from(xml_string.to_string()),
            event: T::from(xml_string.to_string()),
        });
        log::debug!("EvtRender: {:?}", resp);
        log::debug!("Buffer used: {:?}", buffer_used);
        log::debug!("Property count: {:?}", property_count);
        log::debug!("Buffer: {:?}", xml_string);
    }
    events
}
