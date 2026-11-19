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

#[test]
fn the_migrate_seams_are_independent_slots() {
    for point in [Point::AfterSnapshot, Point::AfterSend, Point::BeforeFence] {
        arm(point);
        assert!(trip(point).is_err(), "{point:?}");
        disarm();
        assert!(trip(point).is_ok(), "{point:?}");
    }
    arm(Point::AfterSend);
    assert!(trip(Point::AfterSnapshot).is_ok());
    assert!(trip(Point::BeforeFence).is_ok());
    disarm();
}
