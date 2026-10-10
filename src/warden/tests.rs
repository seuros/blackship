use super::*;

#[test]
fn test_restart_state_backoff() {
    let state = RestartState::new("test_jail");
    assert!(state.should_retry());
    let delay = state.next_delay();
    assert!(delay.is_some());
}

#[test]
fn test_restart_state_reset() {
    let mut state = RestartState::new("test_jail");
    state.attempts = 5;
    state.reset();
    assert_eq!(state.attempts, 0);
}

#[test]
fn test_monitor_ident_prefers_descriptor() {
    assert_eq!(monitor_ident(42, Some(7)), JailIdent::Descriptor(7));
    assert_eq!(monitor_ident(42, None), JailIdent::Jid(42));
}

fn monitored_map(entries: &[(JailIdent, &str, i32)]) -> HashMap<JailIdent, MonitoredJail> {
    entries
        .iter()
        .map(|(ident, name, jid)| {
            (
                *ident,
                MonitoredJail {
                    name: name.to_string(),
                    jid: *jid,
                },
            )
        })
        .collect()
}

#[test]
fn test_has_descriptor_ident_is_per_jail() {
    let map = monitored_map(&[
        (JailIdent::Descriptor(10), "web", 20),
        (JailIdent::Jid(30), "db", 30),
    ]);

    assert!(has_descriptor_ident(&map, "web"));
    assert!(!has_descriptor_ident(&map, "db"));
    assert!(!has_descriptor_ident(&map, "absent"));
}

#[test]
fn test_idents_for_narrows_to_one_jid() {
    let map = monitored_map(&[
        (JailIdent::Descriptor(10), "web", 20),
        (JailIdent::Jid(19), "web", 19),
        (JailIdent::Descriptor(11), "db", 21),
    ]);

    let mut all = idents_for(&map, "web", None);
    all.sort_by_key(|ident| format!("{ident:?}"));
    assert_eq!(all, vec![JailIdent::Descriptor(10), JailIdent::Jid(19)]);

    assert_eq!(
        idents_for(&map, "web", Some(19)),
        vec![JailIdent::Jid(19)],
        "a stale jid must not take the live descriptor registration with it"
    );
    assert!(idents_for(&map, "web", Some(99)).is_empty());
}

#[test]
fn test_intentional_stops_track_jids() {
    let stops = IntentionalStops::default();
    stops.mark(42);

    assert!(stops.contains(42));
    assert!(!stops.contains(43));

    stops.clear(42);
    assert!(!stops.contains(42));
}
