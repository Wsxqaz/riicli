use crate::utils::expand_env_strings;
use crate::winapi::acl::_get_modifiable_path;
use crate::winapi::tasks::{load_tasks, WinTask};

pub fn run() -> Vec<WinTask> {
    let tasks = load_tasks();
    log::debug!("Found {} tasks", tasks.len());
    let mut modifiable_tasks = Vec::new();
    for task in tasks {
        log::debug!("reading actions for task: {}", task.task.name);
        for action in &task.task.definition.actions {
            let mut action = action.clone();
            if let Some(exec_action) = action.exec.as_mut() {
                log::debug!("found exec action: {:?}", exec_action);
                let path = exec_action.path.clone();
                log::debug!("path: {}", path);
                let expanded_path = expand_env_strings(path);
                log::debug!("expanded path: {}", expanded_path);
                let mod_perms = _get_modifiable_path(expanded_path);
                log::debug!("mod_perms: {:?}", mod_perms);
                if mod_perms.len() > 0 {
                    modifiable_tasks.push(task.clone());
                }
            }
        }
    }
    return modifiable_tasks;
}
