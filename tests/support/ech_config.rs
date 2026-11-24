fn append_vector(out: &mut Vec<u8>, value: &[u8]) {
    out.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    out.extend(value);
}

pub fn fixture(public_key_byte: u8, public_name: &[u8], extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut config = vec![1, 0, 0x20];
    append_vector(&mut config, &[public_key_byte; 32]);
    append_vector(&mut config, &[0, 1, 0, 1]);
    config.extend([0, u8::try_from(public_name.len()).unwrap()]);
    config.extend(public_name);
    let mut extension_wire = Vec::new();
    for (kind, value) in extensions {
        extension_wire.extend(kind.to_be_bytes());
        append_vector(&mut extension_wire, value);
    }
    append_vector(&mut config, &extension_wire);
    let mut entry = vec![0xfe, 0x0d];
    append_vector(&mut entry, &config);
    let mut list = Vec::new();
    append_vector(&mut list, &entry);
    list
}
