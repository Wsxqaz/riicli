use crate::winapi::eventlog::{read_eventlog, EventLogGeneric, EventLogLogon, EventLogRecord};
use std::ffi::c_void;
use windows::core::{HRESULT, PCSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::EventLog::{
    OpenEventLogA, ReadEventLogA, EVENTLOGRECORD, EVENTLOG_SEQUENTIAL_READ,
    READ_EVENT_LOG_READ_FLAGS,
};
use windows::Win32::System::SystemServices::EVENTLOG_BACKWARDS_READ;

#[derive(Debug, Clone)]
pub struct Logon {
    pub username: String,
    pub domain: String,
    pub logon_time: String,
    pub logon_type: String,
    pub authentication_package: String,
    pub workstation: String,
    pub logon_server: String,
    pub dns_domain_name: String,
    pub upn: String,
}

#[derive(Debug, Clone)]
pub struct AppLockerLog {
    pub event_id: String,
    pub date: String,
    pub time: String,
    pub user: String,
    pub computer: String,
    pub app_id: String,
    pub app_name: String,
    pub rule_name: String,
    pub action: String,
    pub user_data: String,
}

#[derive(Debug, Clone)]
pub struct PowershellLog {
    pub command_line: String,
}

#[derive(Debug, Clone)]
pub struct RDPSavedServer {
    pub server_name: String,
}

#[derive(Debug, Clone)]
pub struct ComputerDetails {
    pub logons: Vec<EventLogRecord<EventLogLogon>>,
    pub applocker_logs: Vec<EventLogRecord<EventLogLogon>>,
    pub powershell_logs: Vec<EventLogRecord<EventLogGeneric>>,
    pub rdp_saved_servers: Vec<RDPSavedServer>,
}

fn get_logons() -> Vec<EventLogRecord<EventLogLogon>> {
    let mut logons: Vec<EventLogRecord<EventLogLogon>> = Vec::new();
    let events: Vec<EventLogRecord<EventLogLogon>> =
        read_eventlog("Security".to_owned(), "*[System/EventID=4624]".to_owned());
    log::info!("events 4624: {:?}", events.len());
    logons.extend(events);
    let events: Vec<EventLogRecord<EventLogLogon>> =
        read_eventlog("Security".to_owned(), "*[System/EventID=4648]".to_owned());
    log::info!("events 4648: {:?}", events.len());
    logons.extend(events);

    logons
}

fn get_applocker_logs() -> Vec<EventLogRecord<EventLogLogon>> {
    let applocker_logs: Vec<EventLogRecord<EventLogLogon>> = Vec::new();
    applocker_logs
}

fn get_powershell_logs() -> Vec<EventLogRecord<EventLogGeneric>> {
    let events = read_eventlog(
        "Microsoft-Windows-PowerShell/Operational".to_owned(),
        "*".to_owned(),
    );
    log::info!("events: {:?}", events.len());
    events
}

fn get_rdp_saved_servers() -> Vec<RDPSavedServer> {
    let rdp_saved_servers: Vec<RDPSavedServer> = Vec::new();
    rdp_saved_servers
}

pub fn run() -> ComputerDetails {
    let logons = get_logons();
    let applocker_logs = get_applocker_logs();
    let powershell_logs = get_powershell_logs();
    let rdp_saved_servers = get_rdp_saved_servers();

    ComputerDetails {
        logons,
        applocker_logs,
        powershell_logs,
        rdp_saved_servers,
    }
}
