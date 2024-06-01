use std::path::PathBuf;

pub fn run() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let env_path = std::env::var("PATH").unwrap();

    let env_path_dirs = env_path
        .split(";")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();

    for dir in env_path_dirs {
        log::info!("Checking if {} is hijackable", dir);
        match std::fs::metadata(&dir) {
            Err(_) => {
                log::error!("Error getting metadata for {}", dir);
                log::info!("Trying write");
                let mut pp = PathBuf::new();
                for chunk in dir.split("\\") {
                    pp.push(format!("{chunk}\\"));
                    if pp.exists() {
                        log::info!("{} exists, traversing", pp.to_str().unwrap());
                    } else {
                        log::info!("{} does not exist, creating", pp.to_str().unwrap());
                        match std::fs::create_dir(&pp) {
                            Ok(_) => {
                                log::info!("{} created", pp.to_str().unwrap());
                                paths.push(pp.clone());
                                match std::fs::remove_dir(&pp) {
                                    Ok(_) => {
                                        log::info!("{} removed", pp.to_str().unwrap());
                                        break;
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "Error removing {}: {}",
                                            pp.to_str().unwrap(),
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Error creating {}: {}", pp.to_str().unwrap(), e);
                                break;
                            }
                        }
                    }
                }
                continue;
            }
            Ok(md) => {
                if md.permissions().readonly() {
                    log::info!("{} is read-only, skipping", dir);
                    continue;
                } else {
                    log::info!("{} is not read-only, adding to list", dir);
                    paths.push(PathBuf::from(dir.clone()));
                }
            }
        }
    }

    paths
}
