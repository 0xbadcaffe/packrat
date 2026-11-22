use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlanPolicy {
    single_tag_interfaces: BTreeSet<String>,
}

impl VlanPolicy {
    pub fn add_single_tag_interface(&mut self, name: &str) -> Result<(), &'static str> {
        if name.is_empty() || name.len() > 128 || name.starts_with('-')
            || !name.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err("Expected a 1-128 byte printable ASCII interface name that does not start with '-'");
        }
        if self.single_tag_interfaces.contains(name) {
            return Err("Single-tag interface was specified twice");
        }
        if self.single_tag_interfaces.len() == 32 {
            return Err("At most 32 single-tag interfaces may be specified");
        }
        self.single_tag_interfaces.insert(name.to_owned());
        Ok(())
    }

    pub(super) fn expects_single_tag(&self, name: &str) -> bool {
        self.single_tag_interfaces.contains(name)
    }
}
