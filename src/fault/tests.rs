use super::*;

#[test]
fn disarmed_by_default() {
    assert!(trip(Point::AfterZfs).is_ok());
}

#[test]
fn armed_point_fails_only_itself() {
    arm(Point::AfterLease);
    assert!(trip(Point::AfterLease).is_err());
    assert!(trip(Point::AfterZfs).is_ok());
    disarm();
    assert!(trip(Point::AfterLease).is_ok());
}
