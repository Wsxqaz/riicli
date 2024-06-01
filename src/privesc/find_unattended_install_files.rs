use std::path::PathBuf;

pub fn run() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let path = PathBuf::from("c:\\sysprep\\sysprep.inf");
    if path.exists() {
        paths.push(path);
    }
    let path = PathBuf::from("c:\\sysprep\\sysprep.xml");
    if path.exists() {
        paths.push(path);
    }
    let path = PathBuf::from("c:\\sysptep.inf");
    if path.exists() {
        paths.push(path);
    }
    match std::env::var("windir") {
        Err(_) => {}
        Ok(windir) => {
            let path = PathBuf::from(windir.clone());
            let _ = path.join("Panther\\Unattended.xml");
            if path.exists() {
                paths.push(path);
            }
            let path = PathBuf::from(windir.clone());
            let _ = path.join("Panther\\Unattend\\Unattended.xml");
            if path.exists() {
                paths.push(path);
            }
            let path = PathBuf::from(windir.clone());
            let _ = path.join("Panther\\Unattend.xml");
            if path.exists() {
                paths.push(path);
            }
            let path = PathBuf::from(windir.clone());
            let _ = path.join("Panther\\Unattend\\Unattend.xml");
            if path.exists() {
                paths.push(path);
            }
            let path = PathBuf::from(windir.clone());
            let _ = path.join("System32\\Sysprep\\unattend.xml");
            if path.exists() {
                paths.push(path);
            }
            let path = PathBuf::from(windir.clone());
            let _ = path.join("System32\\Sysprep\\Panther\\unattend.xml");
            if path.exists() {
                paths.push(path);
            }
        }
    }

    paths
}
