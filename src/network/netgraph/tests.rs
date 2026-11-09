use super::*;

#[test]
fn test_fill_fixed() {
    let mut buf = [0 as libc::c_char; NG_HOOKSIZ];
    fill_fixed(&mut buf, "link0").unwrap();
    let bytes: Vec<u8> = buf.iter().map(|&c| c.to_ne_bytes()[0]).collect();
    let cstr = CStr::from_bytes_until_nul(&bytes).unwrap();
    assert_eq!(cstr.to_str().unwrap(), "link0");
}

#[test]
fn test_fill_fixed_too_long() {
    let mut buf = [0 as libc::c_char; 4];
    assert!(fill_fixed(&mut buf, "toolong").is_err());
}

#[test]
fn test_fill_fixed_rejects_nul() {
    let mut buf = [0 as libc::c_char; NG_HOOKSIZ];
    assert!(fill_fixed(&mut buf, "has\0nul").is_err());
}
