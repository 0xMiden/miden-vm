use super::FlamegraphProfile;

#[test]
fn record_stack_sanitizes_folded_stack_frames() {
    let mut profile = FlamegraphProfile::default();

    profile.record_stack(["root;proc", "child\nproc"], 3);
    profile.record_stack(["root;proc", "child\nproc"], 2);
    profile.record_stack(["ignored"], 0);

    assert_eq!(profile.total_cycles(), 5);
    assert_eq!(profile.unique_stack_paths(), 1);
    assert_eq!(profile.samples().get("root:proc;child proc"), Some(&5));
    assert!(!profile.samples().contains_key("ignored"));
}
