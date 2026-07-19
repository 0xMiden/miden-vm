//! Pins the huge-page allocator's observable contract on Linux: large
//! allocations live in their own 2 MiB-aligned mapping with the huge-page
//! advice flag set (`hg` in `VmFlags`), so the kernel may back them with
//! transparent huge pages under the default `madvise` policy.

#[global_allocator]
static GLOBAL: miden_prover::huge_alloc::HugePageAlloc = miden_prover::huge_alloc::HugePageAlloc;

#[cfg(target_os = "linux")]
#[test]
fn large_allocations_are_huge_page_advised() {
    use miden_prover::huge_alloc::HUGE_PAGE_SIZE;

    let buf = vec![1u8; 64 * 1024 * 1024];
    let addr = buf.as_ptr() as usize;
    assert_eq!(addr % HUGE_PAGE_SIZE, 0, "mapping must be 2 MiB-aligned");

    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut in_target_mapping = false;
    let mut advised = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ') {
            if let Some((start, end)) = range.split_once('-') {
                if let (Ok(start), Ok(end)) =
                    (usize::from_str_radix(start, 16), usize::from_str_radix(end, 16))
                {
                    in_target_mapping = start <= addr && addr < end;
                }
            }
        }
        if in_target_mapping && line.starts_with("VmFlags:") {
            advised = line.split_whitespace().any(|f| f == "hg");
            break;
        }
    }
    assert!(advised, "mapping containing the buffer must carry the hg (MADV_HUGEPAGE) flag");

    drop(buf);
}

#[cfg(target_os = "linux")]
#[test]
fn small_allocations_use_the_system_allocator_path() {
    // Below the threshold nothing should break or change: just exercise a mix
    // of sizes across the boundary, including reallocation across it.
    let mut v: Vec<u8> = Vec::new();
    for chunk in [1024, 1024 * 1024, 4 * 1024 * 1024] {
        v.resize(chunk, 7);
    }
    assert_eq!(v[v.len() - 1], 7);
}
