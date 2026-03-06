#[derive(Debug, Clone)]
pub struct StringEntry {
    pub offset: String,
    pub length: usize,
    pub value: String,
    pub kind: StringKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StringKind {
    Path,
    Protocol,
    Http,
    Mime,
    Auth,
    Jwt,
    Ip,
    Domain,
    Sensitive,
    Sql,
    Shell,
    Magic,
    Crypto,
    Key,
    Func,
    Net,
}

impl StringKind {
    pub fn label(&self) -> &str {
        match self {
            StringKind::Path      => "path",
            StringKind::Protocol  => "proto",
            StringKind::Http      => "http",
            StringKind::Mime      => "mime",
            StringKind::Auth      => "auth",
            StringKind::Jwt       => "jwt",
            StringKind::Ip        => "ip",
            StringKind::Domain    => "domain",
            StringKind::Sensitive => "⚠ sensitive",
            StringKind::Sql       => "sql",
            StringKind::Shell     => "⚠ shell",
            StringKind::Magic     => "magic",
            StringKind::Crypto    => "crypto",
            StringKind::Key       => "⚠ key",
            StringKind::Func      => "func",
            StringKind::Net       => "net",
        }
    }
    pub fn is_sensitive(&self) -> bool {
        matches!(self, StringKind::Sensitive | StringKind::Shell | StringKind::Key)
    }
}

pub fn all_strings() -> Vec<StringEntry> {
    vec![
        s("0x00001234", "/lib/x86_64-linux-gnu/libc.so.6", StringKind::Path),
        s("0x00002000", "HTTP/1.1", StringKind::Protocol),
        s("0x00002100", "Content-Type: application/json", StringKind::Http),
        s("0x00002200", "Authorization: Bearer", StringKind::Auth),
        s("0x00002300", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", StringKind::Jwt),
        s("0x00002400", "192.168.1.100", StringKind::Ip),
        s("0x00002500", "google.com", StringKind::Domain),
        s("0x00002600", "api.github.com", StringKind::Domain),
        s("0x00002700", "password", StringKind::Sensitive),
        s("0x00002800", "secret_api_key_prod", StringKind::Sensitive),
        s("0x00002900", "SELECT * FROM users WHERE id=", StringKind::Sql),
        s("0x00002a00", "DELETE FROM audit_logs", StringKind::Sql),
        s("0x00002b00", "/etc/passwd", StringKind::Path),
        s("0x00002c00", "/etc/shadow", StringKind::Sensitive),
        s("0x00002d00", "User-Agent: Mozilla/5.0", StringKind::Http),
        s("0x00002e00", "Accept-Encoding: gzip, deflate, br", StringKind::Http),
        s("0x00002f00", "exec('/bin/sh')", StringKind::Shell),
        s("0x00003000", "system(\"/bin/bash -i\")", StringKind::Shell),
        s("0x00003100", "%PDF-1.4", StringKind::Magic),
        s("0x00003200", "PK\x03\x04", StringKind::Magic),
        s("0x00003300", "ssh-rsa AAAA", StringKind::Crypto),
        s("0x00003400", "-----BEGIN RSA PRIVATE KEY-----", StringKind::Key),
        s("0x00003500", "-----BEGIN CERTIFICATE-----", StringKind::Crypto),
        s("0x00003600", "malloc", StringKind::Func),
        s("0x00003700", "free", StringKind::Func),
        s("0x00003800", "printf", StringKind::Func),
        s("0x00003900", "system", StringKind::Shell),
        s("0x00003a00", "socket", StringKind::Net),
        s("0x00003b00", "connect", StringKind::Net),
        s("0x00003c00", "recv", StringKind::Net),
        s("0x00003d00", "send", StringKind::Net),
        s("0x00003e00", "bind", StringKind::Net),
        s("0x00003f00", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", StringKind::Sensitive),
    ]
}

fn s(offset: &str, value: &str, kind: StringKind) -> StringEntry {
    StringEntry { offset: offset.to_string(), length: value.len(), value: value.to_string(), kind }
}
