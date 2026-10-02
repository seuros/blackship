use super::*;

#[test]
fn test_kqueue_creation() {
    let source = JailEventSource::new();
    assert!(
        source.is_ok(),
        "Failed to create kqueue: {:?}",
        source.err()
    );
}

#[test]
fn test_poll_no_events() {
    let source = JailEventSource::new().unwrap();
    let events = source.poll(Some(Duration::ZERO)).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_register_nonexistent_jail() {
    let source = JailEventSource::new().unwrap();
    assert!(source.register_jail(999999).is_err());
}

#[test]
fn test_register_nonexistent_descriptor() {
    let source = JailEventSource::new().unwrap();
    assert!(source.register_jaildesc(999999).is_err());
}

#[test]
fn test_unregister_unknown_ident_is_ok() {
    let source = JailEventSource::new().unwrap();
    assert!(source.unregister(JailIdent::Jid(999999)).is_ok());
    assert!(source.unregister(JailIdent::Descriptor(999999)).is_ok());
}

#[test]
fn test_ident_display_distinguishes_filter() {
    assert_eq!(JailIdent::Jid(7).to_string(), "JID 7");
    assert_eq!(JailIdent::Descriptor(7).to_string(), "jail descriptor 7");
}

#[test]
fn test_event_ident_accessor() {
    let ident = JailIdent::Descriptor(11);
    assert_eq!(JailEvent::Remove { ident }.ident(), ident);
    assert_eq!(
        JailEvent::Child {
            ident,
            coalesced: true
        }
        .ident(),
        ident
    );
}
