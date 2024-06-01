use serde::{Deserialize, Serialize};

use crate::winapi::wmi::init_com;
use core::mem::ManuallyDrop;
use windows_core::Interface;
use windows::core::{VARIANT, BSTR, HRESULT, PWSTR};
use windows::Win32::Foundation::{E_INVALIDARG, E_OUTOFMEMORY, S_FALSE, S_OK, VARIANT_BOOL};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::TaskScheduler::{
    CLSID_CTaskScheduler, IAction, IActionCollection, IComHandlerAction, IEmailAction,
    IEnumWorkItems, IExecAction, IIdleSettings, INetworkSettings, IRegisteredTask,
    IRegisteredTaskCollection, IRepetitionPattern, IShowMessageAction, ITask, ITaskFolder,
    ITaskFolderCollection, ITaskScheduler, ITaskService, ITaskSettings, TaskScheduler,
    TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC, TASK_ACTION_SEND_EMAIL, TASK_ACTION_SHOW_MESSAGE,
    TASK_ACTION_TYPE, TASK_COMPATIBILITY, TASK_ENUM_HIDDEN, TASK_INSTANCES_POLICY, TASK_LOGON_TYPE,
    TASK_RUNLEVEL_TYPE, TASK_TRIGGER_TYPE2,
};
use windows::Win32::System::Variant::{
    VariantInit
};

use std::io::BufReader;
use std::io::Read;

fn load_subfolders(folder: &ITaskFolder) -> Vec<ITaskFolder> {
    unsafe {
        let sub_folders: ITaskFolderCollection = folder.GetFolders(0).unwrap();
        let num_sub_folders = sub_folders.Count().unwrap();
        let mut resp: Vec<ITaskFolder> = vec![];
        for _i in 1..(num_sub_folders + 1) {
            let var: VARIANT = std::mem::zeroed();
            let sub_folder: ITaskFolder = sub_folders.get_Item(&var).unwrap();
            let _sub_folders = load_subfolders(&sub_folder);
            resp.push(sub_folder);
            resp.extend(_sub_folders);
        }
        resp
    }
}

fn load_subfolder_tasks(folder: &ITaskFolder) -> Vec<WinTask> {
    unsafe {
        let tasks: IRegisteredTaskCollection = folder.GetTasks(TASK_ENUM_HIDDEN.0).unwrap();
        let task_count = tasks.Count().unwrap();
        let mut resp: Vec<WinTask> = vec![];

        for _i in 1..(task_count + 1) {
            let var: VARIANT = std::mem::zeroed();
            let task: IRegisteredTask = tasks.get_Item(&var).unwrap();
            let _task = Task::from(task);
            resp.push(WinTask {
                folder_name: folder.Name().unwrap().to_string(),
                folder_path: folder.Path().unwrap().to_string(),
                task: _task,
            });
        }
        resp
    }
}

#[allow(unreachable_patterns, unused_variables, non_snake_case)]
pub fn load_tasks() -> Vec<WinTask> {
    unsafe {
        let task_service: ITaskService =
            match CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) {
                Ok(task_service) => task_service,
                Err(e) => {
                    log::error!("CoCreateInstance Error {:?}", e);
                    let _ = init_com();
                    CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).unwrap()
                }
            };

        let _ = task_service
            .Connect(&VariantInit(), &VariantInit(), &VariantInit(), &VariantInit())
            .unwrap();

        let mut resp: Vec<WinTask> = vec![];
        let root_folder: ITaskFolder = task_service.GetFolder(&BSTR::from("\\")).unwrap();
        let _root_tasks = load_subfolder_tasks(&root_folder);
        resp.extend(_root_tasks);
        let folder_name: BSTR = root_folder.Name().unwrap();
        let folder_path: BSTR = root_folder.Path().unwrap();

        let sub_folders: ITaskFolderCollection = root_folder.GetFolders(0).unwrap();
        let num_sub_folders: Vec<ITaskFolder> = load_subfolders(&root_folder);
        log::debug!("sub_folders: {:?}", num_sub_folders.len());
        for sub_folder in num_sub_folders {
            let _tasks = load_subfolder_tasks(&sub_folder);
            resp.extend(_tasks);
        }
        resp
    }
}

impl From<IRegisteredTask> for Task {
    fn from(task: IRegisteredTask) -> Self {
        unsafe {
            let task_name: String = task.Name().unwrap().to_string();
            let task_path: String = task.Path().unwrap().to_string();
            let task_state: String = task.State().unwrap().0.to_string();
            let task_enabled: String = task.Enabled().unwrap().0.to_string();
            let task_last_run: String = task.LastRunTime().unwrap().to_string();
            let task_last_result: String = task.LastTaskResult().unwrap().to_string();
            let task_missed_runs: String = task.NumberOfMissedRuns().unwrap().to_string();
            let task_next_run: String = task.NextRunTime().unwrap().to_string();
            // let task_xml: String = task.Xml().unwrap().to_string();
            let task_definition = task.Definition().unwrap();

            let task_action_collection: IActionCollection = task_definition.Actions().unwrap();
            let mut task_action_count = 0;
            let _ = task_action_collection
                .Count(&mut task_action_count)
                .unwrap();
            let mut task_actions: Vec<TaskAction> = vec![];
            log::debug!("task_action_count: {:?}", task_action_count);
            for i in 1..(task_action_count + 1) {
                let action = task_action_collection.get_Item(i).unwrap();
                let paction_type: *mut TASK_ACTION_TYPE =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut TASK_ACTION_TYPE>(),
                        8,
                    )) as *mut TASK_ACTION_TYPE;
                let _ = action.Type(paction_type).unwrap();
                match *paction_type {
                    TASK_ACTION_EXEC => {
                        let exec_action: IExecAction = action.cast().unwrap();
                        let path: *mut BSTR =
                            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                std::mem::size_of::<*mut BSTR>(),
                                8,
                            )) as *mut BSTR;
                        let _ = exec_action.Path(path).unwrap();
                        let arguments: *mut BSTR =
                            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                std::mem::size_of::<*mut BSTR>(),
                                8,
                            )) as *mut BSTR;
                        let _ = exec_action.Arguments(arguments).unwrap();
                        let working_directory: *mut BSTR =
                            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                std::mem::size_of::<*mut BSTR>(),
                                8,
                            )) as *mut BSTR;
                        let _ = exec_action.WorkingDirectory(working_directory).unwrap();
                        task_actions.push(TaskAction {
                            action_type: "exec".to_string(),
                            com_handler: None,
                            exec: Some(TaskExecAction {
                                path: (*path).to_string(),
                                arguments: (*arguments).to_string(),
                                working_directory: (*working_directory).to_string(),
                            }),
                        });
                    }
                    TASK_ACTION_COM_HANDLER => {
                        let com_handler_action: IComHandlerAction = action.cast().unwrap();
                        let clsid: *mut BSTR =
                            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                std::mem::size_of::<*mut BSTR>(),
                                8,
                            )) as *mut BSTR;
                        let _ = com_handler_action.ClassId(clsid).unwrap();
                        let data: *mut BSTR =
                            std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                                std::mem::size_of::<*mut BSTR>(),
                                8,
                            )) as *mut BSTR;
                        let _ = com_handler_action.Data(data).unwrap();
                        task_actions.push(TaskAction {
                            action_type: "com_handler".to_string(),
                            com_handler: Some(TaskComHandlerAction {
                                clsid: (*clsid).to_string(),
                                data: (*data).to_string(),
                            }),
                            exec: None,
                        });
                    }
                    _ => {
                        task_actions.push(TaskAction {
                            action_type: "unknown".to_string(),
                            com_handler: None,
                            exec: None,
                        });
                    }
                }
            }

            let registration_info = task_definition.RegistrationInfo().unwrap();
            let author: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = registration_info.Author(author).unwrap();
            let description: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = registration_info.Description(description).unwrap();
            let date: *mut BSTR = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<*mut BSTR>(),
                8,
            )) as *mut BSTR;
            let _ = registration_info.Date(date).unwrap();
            let documentation: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = registration_info.Documentation(documentation).unwrap();
            let version: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = registration_info.Version(version).unwrap();
            let uri: *mut BSTR = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<*mut BSTR>(),
                8,
            )) as *mut BSTR;
            let _ = registration_info.URI(uri).unwrap();
            let source: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = registration_info.Source(source).unwrap();

            let task_settings = task_definition.Settings().unwrap();
            let allow_demand_start: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings.AllowDemandStart(allow_demand_start).unwrap();
            let allow_hard_terminate: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings
                .AllowHardTerminate(allow_hard_terminate)
                .unwrap();
            let compatibility: *mut TASK_COMPATIBILITY =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut TASK_COMPATIBILITY>(),
                    8,
                )) as *mut TASK_COMPATIBILITY;
            let _ = task_settings.Compatibility(compatibility).unwrap();
            let delete_expired_task_after: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_settings
                .DeleteExpiredTaskAfter(delete_expired_task_after)
                .unwrap();
            let disallow_start_if_on_batteries: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings
                .DisallowStartIfOnBatteries(disallow_start_if_on_batteries)
                .unwrap();
            let enabled: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings.Enabled(enabled).unwrap();
            let execution_time_limit: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_settings
                .ExecutionTimeLimit(execution_time_limit)
                .unwrap();
            let hidden: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings.Hidden(hidden).unwrap();
            let idle_settings: IIdleSettings = task_settings.IdleSettings().unwrap();
            let idle_duraiton: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = idle_settings.IdleDuration(idle_duraiton).unwrap();
            let wait_timeout: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = idle_settings.WaitTimeout(wait_timeout).unwrap();
            let stop_on_idle_end: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = idle_settings.StopOnIdleEnd(stop_on_idle_end).unwrap();
            let restart_on_idle: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = idle_settings.RestartOnIdle(restart_on_idle).unwrap();
            let multiple_instances_policy: *mut TASK_INSTANCES_POLICY =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut TASK_INSTANCES_POLICY>(),
                    8,
                )) as *mut TASK_INSTANCES_POLICY;
            let _ = task_settings
                .MultipleInstances(multiple_instances_policy)
                .unwrap();
            let network_settings: INetworkSettings = task_settings.NetworkSettings().unwrap();
            let id: *mut BSTR = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<*mut BSTR>(),
                8,
            )) as *mut BSTR;
            let _ = network_settings.Id(id).unwrap();
            let name: *mut BSTR = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<*mut BSTR>(),
                8,
            )) as *mut BSTR;
            let _ = network_settings.Name(name).unwrap();
            let priority: *mut i32 = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut i32>(), 8),
            ) as *mut i32;
            let _ = task_settings.Priority(priority).unwrap();
            let restart_count: *mut i32 = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut i32>(), 8),
            ) as *mut i32;
            let _ = task_settings.RestartCount(restart_count).unwrap();
            let restart_interval: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_settings.RestartInterval(restart_interval).unwrap();
            let run_only_if_idle: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings.RunOnlyIfIdle(run_only_if_idle).unwrap();
            let run_only_if_network_available: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings
                .RunOnlyIfNetworkAvailable(run_only_if_network_available)
                .unwrap();
            let start_when_available: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings
                .StartWhenAvailable(start_when_available)
                .unwrap();
            let stop_if_going_on_batteries: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings
                .StopIfGoingOnBatteries(stop_if_going_on_batteries)
                .unwrap();
            let wake_to_run: *mut VARIANT_BOOL =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut VARIANT_BOOL>(),
                    8,
                )) as *mut VARIANT_BOOL;
            let _ = task_settings.WakeToRun(wake_to_run).unwrap();

            let task_principal = task_definition.Principal().unwrap();
            let display_name: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_principal.DisplayName(display_name).unwrap();
            let group_id: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_principal.GroupId(group_id).unwrap();
            let id: *mut BSTR = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                std::mem::size_of::<*mut BSTR>(),
                8,
            )) as *mut BSTR;
            let _ = task_principal.Id(id).unwrap();
            let logon_type: *mut TASK_LOGON_TYPE =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut TASK_LOGON_TYPE>(),
                    8,
                )) as *mut TASK_LOGON_TYPE;
            let _ = task_principal.LogonType(logon_type).unwrap();
            let run_level: *mut TASK_RUNLEVEL_TYPE =
                std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                    std::mem::size_of::<*mut TASK_RUNLEVEL_TYPE>(),
                    8,
                )) as *mut TASK_RUNLEVEL_TYPE;
            let _ = task_principal.RunLevel(run_level).unwrap();
            let user_id: *mut BSTR = std::alloc::alloc(
                std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<*mut BSTR>(), 8),
            ) as *mut BSTR;
            let _ = task_principal.UserId(user_id).unwrap();

            let mut triggers: Vec<TaskTrigger> = vec![];
            let task_triggers = task_definition.Triggers().unwrap();
            let mut trigger_count = 0;
            let _ = task_triggers.Count(&mut trigger_count).unwrap();
            for i in 1..(trigger_count + 1) {
                let trigger = task_triggers.get_Item(i).unwrap();
                let enabled: *mut VARIANT_BOOL =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut VARIANT_BOOL>(),
                        8,
                    )) as *mut VARIANT_BOOL;
                let _ = trigger.Enabled(enabled).unwrap();
                let end_boundary: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = trigger.EndBoundary(end_boundary).unwrap();
                let execution_time_limit: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = trigger.ExecutionTimeLimit(execution_time_limit).unwrap();
                let id: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = trigger.Id(id).unwrap();
                let repetition: IRepetitionPattern = trigger.Repetition().unwrap();
                let duration: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = repetition.Duration(duration).unwrap();
                let interval: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = repetition.Interval(interval).unwrap();
                let stop_at_duration_end: *mut VARIANT_BOOL =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut VARIANT_BOOL>(),
                        8,
                    )) as *mut VARIANT_BOOL;
                let _ = repetition.StopAtDurationEnd(stop_at_duration_end).unwrap();
                let start_boundary: *mut BSTR =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut BSTR>(),
                        8,
                    )) as *mut BSTR;
                let _ = trigger.StartBoundary(start_boundary).unwrap();
                let trigger_type: *mut TASK_TRIGGER_TYPE2 =
                    std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                        std::mem::size_of::<*mut TASK_TRIGGER_TYPE2>(),
                        8,
                    )) as *mut TASK_TRIGGER_TYPE2;
                let _ = trigger.Type(trigger_type).unwrap();
                triggers.push(TaskTrigger {
                    enabled: (*enabled).0.to_string(),
                    end_boundary: (*end_boundary).to_string(),
                    execution_time_limit: (*execution_time_limit).to_string(),
                    id: (*id).to_string(),
                    repetition: TaskRepetition {
                        duration: (*duration).to_string(),
                        interval: (*interval).to_string(),
                        stop_at_duration_end: (*stop_at_duration_end).0.to_string(),
                    },
                    start_boundary: (*start_boundary).to_string(),
                    trigger_type: (*trigger_type).0.to_string(),
                });
            }

            Task {
                name: task_name,
                path: task_path,
                state: task_state,
                enabled: task_enabled,
                last_run: task_last_run,
                last_result: task_last_result,
                missed_runs: task_missed_runs,
                next_run: task_next_run,
                // xml: task_xml,
                definition: TaskDefinition {
                    actions: task_actions,
                    registration_info: TaskRegistrationInfo {
                        author: (*author).to_string(),
                        description: (*description).to_string(),
                        date: (*date).to_string(),
                        documentation: (*documentation).to_string(),
                        version: (*version).to_string(),
                        uri: (*uri).to_string(),
                        source: (*source).to_string(),
                    },
                    settings: TaskSettings {
                        allow_demand_start: (*allow_demand_start).0.to_string(),
                        allow_hard_terminate: (*allow_hard_terminate).0.to_string(),
                        compatibility: (*compatibility).0.to_string(),
                        delete_expired_task_after: (*delete_expired_task_after).to_string(),
                        disallow_start_if_on_batteries: (*disallow_start_if_on_batteries)
                            .0
                            .to_string(),
                        enabled: (*enabled).0.to_string(),
                        execution_time_limit: (*execution_time_limit).to_string(),
                        hidden: (*hidden).0.to_string(),
                        idle_settings: TaskIdleSettings {
                            idle_duraiton: (*idle_duraiton).to_string(),
                            wait_timeout: (*wait_timeout).to_string(),
                            stop_on_idle_end: (*stop_on_idle_end).0.to_string(),
                            restart_on_idle: (*restart_on_idle).0.to_string(),
                        },
                        multiple_instances_policy: (*multiple_instances_policy).0.to_string(),
                        network_settings: TaskNetworkSettings {
                            id: (*id).to_string(),
                            name: (*name).to_string(),
                        },
                        priority: (*priority).to_string(),
                        restart_count: (*restart_count).to_string(),
                        restart_interval: (*restart_interval).to_string(),
                        run_only_if_idle: (*run_only_if_idle).0.to_string(),
                        run_only_if_network_available: (*run_only_if_network_available)
                            .0
                            .to_string(),
                        start_when_available: (*start_when_available).0.to_string(),
                        stop_if_going_on_batteries: (*stop_if_going_on_batteries).0.to_string(),
                        wake_to_run: (*wake_to_run).0.to_string(),
                    },
                    principal: TaskPrincipal {
                        display_name: (*display_name).to_string(),
                        group_id: (*group_id).to_string(),
                        id: (*id).to_string(),
                        logon_type: (*logon_type).0.to_string(),
                        run_level: (*run_level).0.to_string(),
                        user_id: (*user_id).to_string(),
                    },
                    triggers: triggers,
                },
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WinTask {
    pub folder_name: String,
    pub folder_path: String,
    pub task: Task,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Task {
    pub name: String,
    pub path: String,
    pub state: String,
    pub enabled: String,
    pub last_run: String,
    pub last_result: String,
    pub missed_runs: String,
    pub next_run: String,
    pub definition: TaskDefinition,
    // pub xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub actions: Vec<TaskAction>,
    pub registration_info: TaskRegistrationInfo,
    pub settings: TaskSettings,
    pub principal: TaskPrincipal,
    pub triggers: Vec<TaskTrigger>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskAction {
    pub action_type: String,
    pub com_handler: Option<TaskComHandlerAction>,
    pub exec: Option<TaskExecAction>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskExecAction {
    pub path: String,
    pub arguments: String,
    pub working_directory: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskComHandlerAction {
    pub clsid: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskRegistrationInfo {
    pub author: String,
    pub description: String,
    pub date: String,
    pub documentation: String,
    pub source: String,
    pub uri: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskSettings {
    pub allow_demand_start: String,
    pub allow_hard_terminate: String,
    pub compatibility: String,
    pub delete_expired_task_after: String,
    pub disallow_start_if_on_batteries: String,
    pub enabled: String,
    pub execution_time_limit: String,
    pub hidden: String,
    pub idle_settings: TaskIdleSettings,
    pub multiple_instances_policy: String,
    pub network_settings: TaskNetworkSettings,
    pub priority: String,
    pub restart_count: String,
    pub restart_interval: String,
    pub run_only_if_idle: String,
    pub run_only_if_network_available: String,
    pub start_when_available: String,
    pub stop_if_going_on_batteries: String,
    pub wake_to_run: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskIdleSettings {
    pub idle_duraiton: String,
    pub wait_timeout: String,
    pub stop_on_idle_end: String,
    pub restart_on_idle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskNetworkSettings {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskPrincipal {
    pub display_name: String,
    pub group_id: String,
    pub id: String,
    pub logon_type: String,
    pub run_level: String,
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskTrigger {
    pub enabled: String,
    pub end_boundary: String,
    pub execution_time_limit: String,
    pub id: String,
    pub repetition: TaskRepetition,
    pub start_boundary: String,
    pub trigger_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaskRepetition {
    pub duration: String,
    pub interval: String,
    pub stop_at_duration_end: String,
}
