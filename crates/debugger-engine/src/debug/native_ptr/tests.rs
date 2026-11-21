use super::NativePtr;

/// Checks that only pointers with a zero byte offset are element-aligned.
#[test]
fn native_ptr_is_element_aligned_requires_zero_offset() {
    assert!(NativePtr::new(5, 0).is_element_aligned());
    assert!(!NativePtr::new(5, 3).is_element_aligned());
    assert!(NativePtr::from_ptr(20).is_element_aligned());
    assert!(!NativePtr::from_ptr(21).is_element_aligned());
}

/// Checks that word alignment requires both a zero offset and an address that is a multiple of 4.
#[test]
fn native_ptr_is_word_aligned_requires_word_boundary() {
    assert!(NativePtr::new(0, 0).is_word_aligned());
    assert!(NativePtr::new(8, 0).is_word_aligned());
    assert!(!NativePtr::new(6, 0).is_word_aligned());
    assert!(!NativePtr::new(8, 1).is_word_aligned());
    assert!(NativePtr::from_ptr(32).is_word_aligned());
    assert!(!NativePtr::from_ptr(20).is_word_aligned());
}
