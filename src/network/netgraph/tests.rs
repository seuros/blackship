use super::*;

#[test]
fn test_fill_fixed() {
    let mut buf = [0i8; NG_HOOKSIZ];
    fill_fixed(&mut buf, "link0").unwrap();
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(cstr.to_str().unwrap(), "link0");
}

#[test]
fn test_fill_fixed_too_long() {
    let mut buf = [0i8; 4];
    assert!(fill_fixed(&mut buf, "toolong").is_err());
}

#[test]
fn test_fill_fixed_rejects_nul() {
    let mut buf = [0i8; NG_HOOKSIZ];
    assert!(fill_fixed(&mut buf, "has\0nul").is_err());
}
