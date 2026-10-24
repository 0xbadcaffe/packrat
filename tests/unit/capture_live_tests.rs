use super::*;

#[test]
fn missing_capture_device_returns_an_error_without_panicking() {
    let source = LiveCapture {
        iface: "packrat-device-that-does-not-exist".into(),
        filter: None,
    };
    assert!(open_capture(&source).is_err());
}
