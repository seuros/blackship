use super::*;

#[test]
fn fence_value_names_host_dataset_and_time() {
    assert_eq!(
        fence_value("root@bastion", "zroot/jails/web", 1_794_000_000),
        "bastion/zroot/jails/web@1794000000"
    );
    assert_eq!(
        fence_value("bastion", "zroot/jails/web", 5),
        "bastion/zroot/jails/web@5"
    );
}

#[test]
fn refusal_names_the_destination_and_the_way_out() {
    let message = Error::migrated("spk-web", "bastion/zroot/jails/spk-web@1794000000").to_string();
    assert!(message.contains("bastion/zroot/jails/spk-web"), "{message}");
    assert!(message.contains("1794000000"), "{message}");
    assert!(message.contains("blackship unfence spk-web"), "{message}");
}

#[test]
fn refusal_survives_a_fence_without_a_time() {
    let message = Error::migrated("web", "bastion/zroot/web").to_string();
    assert!(message.contains("bastion/zroot/web"), "{message}");
}

#[test]
fn a_cloned_jail_is_sent_as_a_full_stream() {
    assert_eq!(
        send_args("zroot/j/web@s", true),
        ["send", "-p", "zroot/j/web@s"]
    );
    assert_eq!(
        send_args("zroot/j/web@s", false),
        ["send", "-R", "zroot/j/web@s"]
    );
}
