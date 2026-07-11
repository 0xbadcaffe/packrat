//! Optional Landlock filesystem-write sandbox.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RuntimeGuardStatus {
    pub detail: String,
}

pub fn default_write_paths() -> Result<Vec<PathBuf>, String> {
    let mut paths = vec![
        std::env::current_dir().map_err(|error| format!("resolve working directory: {error}"))?,
        std::env::temp_dir(),
    ];
    if let Some(config) = dirs_next::config_dir() {
        paths.push(config.join("packrat"));
    }
    if let Some(data) = dirs_next::data_dir() {
        paths.push(data.join("packrat"));
    }
    paths.sort();
    paths.dedup();
    for path in &paths {
        std::fs::create_dir_all(path)
            .map_err(|error| format!("prepare sandbox path {}: {error}", path.display()))?;
    }
    Ok(paths)
}

pub fn apply(write_paths: &[PathBuf]) -> Result<RuntimeGuardStatus, String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
            RulesetCreatedAttr,
        };

        let abi = ABI::V4;
        let all = AccessFs::from_all(abi);
        let read = AccessFs::from_read(abi);
        let mut ruleset = Ruleset::default()
            .handle_access(all)
            .map_err(|error| format!("configure Landlock: {error}"))?
            .create()
            .map_err(|error| format!("create Landlock ruleset: {error}"))?
            .add_rule(PathBeneath::new(
                PathFd::new("/").map_err(|error| format!("open root for Landlock: {error}"))?,
                read,
            ))
            .map_err(|error| format!("allow filesystem reads: {error}"))?;

        for path in write_paths {
            ruleset = ruleset.add_rule(PathBeneath::new(
                PathFd::new(path).map_err(|error| format!("open sandbox path {}: {error}", path.display()))?,
                all,
            )).map_err(|error| format!("allow sandbox path {}: {error}", path.display()))?;
        }
        let status = ruleset.restrict_self()
            .map_err(|error| format!("activate Landlock: {error}"))?;
        Ok(RuntimeGuardStatus { detail: format!("Landlock active: {status:?}") })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = write_paths;
        Err("--sandbox currently requires Linux Landlock".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_include_working_and_temporary_directories() {
        let paths = default_write_paths().unwrap();
        assert!(paths.contains(&std::env::current_dir().unwrap()));
        assert!(paths.contains(&std::env::temp_dir()));
    }
}
