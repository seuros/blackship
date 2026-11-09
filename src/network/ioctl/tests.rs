use super::*;

/// Interfaces created by a test, destroyed even when an assertion fails.
struct Interfaces(Vec<String>);

impl Drop for Interfaces {
    fn drop(&mut self) {
        // Members first, bridge last; destroying epairNa takes epairNb with it.
        for name in self.0.iter().rev() {
            // May already be gone.
            let _ = destroy_interface(name);
        }
    }
}

#[test]
#[ignore = "needs root, if_bridge and if_epair"]
fn bridge_list_members_sees_every_member() {
    crate::sys::load_modules(&["if_bridge", "bridgestp", "if_epair"]).unwrap();
    let mut created = Interfaces(vec![create_interface("bridge", None).unwrap()]);
    let bridge = created.0[0].clone();
    let mut expected = Vec::new();
    // More than the 16 the first buffer used to hold.
    for _ in 0..20 {
        let host_side = create_interface("epair", None).unwrap();
        created.0.push(host_side.clone());
        bridge_add_member(&bridge, &host_side).unwrap();
        expected.push(host_side);
    }

    let mut members = bridge_list_members(&bridge).unwrap();
    members.sort();
    expected.sort();
    assert_eq!(members, expected);
}

#[test]
#[ignore = "needs root, if_bridge with VLAN filtering and if_epair"]
fn tagged_vlans_reach_the_kernel() {
    crate::sys::load_modules(&["if_bridge", "bridgestp", "if_epair"]).unwrap();
    let mut created = Interfaces(vec![create_interface("bridge", None).unwrap()]);
    let bridge = created.0[0].clone();
    bridge_enable_vlan_filtering(&bridge).unwrap();
    let member = create_interface("epair", None).unwrap();
    created.0.push(member.clone());
    bridge_add_member(&bridge, &member).unwrap();

    // Word boundaries of a 64-bit bitset: bits 63/64, and the last valid id.
    bridge_set_tagged_vlans(&bridge, &member, &[10, 63, 64, 100, 4094]).unwrap();

    let out = std::process::Command::new("/sbin/ifconfig")
        .arg(&bridge)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let tagged = text
        .lines()
        .find_map(|line| line.split_once(" tagged ").map(|(_, vlans)| vlans))
        .unwrap_or_else(|| panic!("no tagged line in:\n{text}"));
    assert_eq!(tagged.trim(), "10,63-64,100,4094", "ifconfig said:\n{text}");
}
