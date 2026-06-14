#[test]
fn digest_extracts_deepest_post_compression_word() {
    let source = "
    use miden::core::crypto::hashes::eidos

    begin
        # Build a post-compression BlakeG state: [CV, ZERO, DIGEST].
        push.44.43.42.41
        padw
        push.4.3.2.1

        exec.eidos::digest

        push.44.43.42.41
        assert_eqw.err=\"eidos::digest must extract DIGEST\"
    end
    ";

    build_test!(source, &[]).expect_stack(&[]);
}
