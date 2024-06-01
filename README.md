# riicli

windows privesc + recon in rust

## build

```bash
cargo build --target x86_64-pc-windows-gnu 
```

## how to use

```powershell
.\riicli.exe --help
```

## features - privesc

- [x] User Has Local Admin
- [x] User In Local Admin Group
- [x] Get Process Token Privileges
- [x] Get [Unquoted Service Paths](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb)
- [x] Set Service Binary Path
- [x] Get Modifiable Services
- [x] Add/Remove token handle perms
- [x] Get all SIDs with perms to modify path

## useful links

* [Rust for Windows docs](https://microsoft.github.io/windows-docs-rs/doc/windows/)
* [ACE types + flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
* [Service Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

## references

* [WMI Crate](https://docs.rs/crate/wmi/latest)
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
* [PEASS-ng](https://github.com/carlospolop/PEASS-ng)

