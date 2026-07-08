/// This trait represents an alignable primitive integer value representing an address
pub trait Alignable {
    /// This function computes the offset, in bytes, needed to align `self` upwards so that
    /// it is aligned to `align` bytes.
    ///
    /// The following must be true, or this function will panic:
    ///
    /// * `align` is non-zero
    /// * `align` is a power of two
    fn align_offset(self, align: Self) -> Self;
    /// This function aligns `self` to the specified alignment (in bytes), aligning upwards.
    ///
    /// The following must be true, or this function will panic:
    ///
    /// * `align` is non-zero
    /// * `align` is a power of two
    /// * `self` + `align` must be less than `Self::MAX`
    fn align_up(self, align: Self) -> Self;

    /// Compute the nearest power of two less than or equal to `self`
    fn prev_power_of_two(self) -> Self;
}

macro_rules! alignable {
    ($($ty:ty),+) => {
        $(
            alignable_impl!($ty);
        )*
    };
}

macro_rules! alignable_impl {
    ($ty:ty) => {
        #[allow(unstable_name_collisions)]
        impl Alignable for $ty {
            #[inline]
            fn align_offset(self, align: Self) -> Self {
                self.align_up(align) - self
            }

            #[inline]
            fn align_up(self, align: Self) -> Self {
                assert_ne!(align, 0);
                assert!(align.is_power_of_two());
                self.checked_next_multiple_of(align).expect("alignment overflow")
            }

            #[inline]
            fn prev_power_of_two(self) -> Self {
                if self.is_power_of_two() {
                    self
                } else {
                    core::cmp::max(self.next_power_of_two() / 2, 1)
                }
            }
        }
    };
}

alignable!(u8, u16, u32, u64, usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignable_next_multiple_of() {
        let addr = 0u32;
        assert_eq!(addr.next_multiple_of(1), 0);
        assert_eq!(addr.next_multiple_of(2), 0);
        assert_eq!(addr.next_multiple_of(4), 0);
        assert_eq!(addr.next_multiple_of(8), 0);
        assert_eq!(addr.next_multiple_of(16), 0);
        assert_eq!(addr.next_multiple_of(32), 0);

        let addr = 1u32;
        assert_eq!(addr.next_multiple_of(1), 1);
        assert_eq!(addr.next_multiple_of(2), 2);
        assert_eq!(addr.next_multiple_of(4), 4);
        assert_eq!(addr.next_multiple_of(8), 8);
        assert_eq!(addr.next_multiple_of(16), 16);
        assert_eq!(addr.next_multiple_of(32), 32);

        let addr = 2u32;
        assert_eq!(addr.next_multiple_of(1), 2);
        assert_eq!(addr.next_multiple_of(2), 2);
        assert_eq!(addr.next_multiple_of(4), 4);
        assert_eq!(addr.next_multiple_of(8), 8);
        assert_eq!(addr.next_multiple_of(16), 16);
        assert_eq!(addr.next_multiple_of(32), 32);

        let addr = 3u32;
        assert_eq!(addr.next_multiple_of(1), 3);
        assert_eq!(addr.next_multiple_of(2), 4);
        assert_eq!(addr.next_multiple_of(4), 4);
        assert_eq!(addr.next_multiple_of(8), 8);
        assert_eq!(addr.next_multiple_of(16), 16);
        assert_eq!(addr.next_multiple_of(32), 32);

        let addr = 127u32;
        assert_eq!(addr.next_multiple_of(1), 127);
        assert_eq!(addr.next_multiple_of(2), 128);
        assert_eq!(addr.next_multiple_of(4), 128);
        assert_eq!(addr.next_multiple_of(8), 128);
        assert_eq!(addr.next_multiple_of(16), 128);
        assert_eq!(addr.next_multiple_of(32), 128);

        let addr = 130u32;
        assert_eq!(addr.next_multiple_of(1), 130);
        assert_eq!(addr.next_multiple_of(2), 130);
        assert_eq!(addr.next_multiple_of(4), 132);
        assert_eq!(addr.next_multiple_of(8), 136);
        assert_eq!(addr.next_multiple_of(16), 144);
        assert_eq!(addr.next_multiple_of(32), 160);
    }

    #[test]
    fn alignable_align_offset_test() {
        let addr = 0u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 0);
        assert_eq!(addr.align_offset(4), 0);
        assert_eq!(addr.align_offset(8), 0);
        assert_eq!(addr.align_offset(16), 0);
        assert_eq!(addr.align_offset(32), 0);

        let addr = 1u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 1);
        assert_eq!(addr.align_offset(4), 3);
        assert_eq!(addr.align_offset(8), 7);
        assert_eq!(addr.align_offset(16), 15);
        assert_eq!(addr.align_offset(32), 31);

        let addr = 2u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 0);
        assert_eq!(addr.align_offset(4), 2);
        assert_eq!(addr.align_offset(8), 6);
        assert_eq!(addr.align_offset(16), 14);
        assert_eq!(addr.align_offset(32), 30);

        let addr = 3u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 1);
        assert_eq!(addr.align_offset(4), 1);
        assert_eq!(addr.align_offset(8), 5);
        assert_eq!(addr.align_offset(16), 13);
        assert_eq!(addr.align_offset(32), 29);

        let addr = 127u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 1);
        assert_eq!(addr.align_offset(4), 1);
        assert_eq!(addr.align_offset(8), 1);
        assert_eq!(addr.align_offset(16), 1);
        assert_eq!(addr.align_offset(32), 1);

        let addr = 130u32;
        assert_eq!(addr.align_offset(1), 0);
        assert_eq!(addr.align_offset(2), 0);
        assert_eq!(addr.align_offset(4), 2);
        assert_eq!(addr.align_offset(8), 6);
        assert_eq!(addr.align_offset(16), 14);
        assert_eq!(addr.align_offset(32), 30);
    }

    #[test]
    fn alignable_align_up_test() {
        let addr = 0u32;
        assert_eq!(addr.align_up(1), 0);
        assert_eq!(addr.align_up(2), 0);
        assert_eq!(addr.align_up(4), 0);
        assert_eq!(addr.align_up(8), 0);
        assert_eq!(addr.align_up(16), 0);
        assert_eq!(addr.align_up(32), 0);

        let addr = 1u32;
        assert_eq!(addr.align_up(1), 1);
        assert_eq!(addr.align_up(2), 2);
        assert_eq!(addr.align_up(4), 4);
        assert_eq!(addr.align_up(8), 8);
        assert_eq!(addr.align_up(16), 16);
        assert_eq!(addr.align_up(32), 32);

        let addr = 2u32;
        assert_eq!(addr.align_up(1), 2);
        assert_eq!(addr.align_up(2), 2);
        assert_eq!(addr.align_up(4), 4);
        assert_eq!(addr.align_up(8), 8);
        assert_eq!(addr.align_up(16), 16);
        assert_eq!(addr.align_up(32), 32);

        let addr = 3u32;
        assert_eq!(addr.align_up(1), 3);
        assert_eq!(addr.align_up(2), 4);
        assert_eq!(addr.align_up(4), 4);
        assert_eq!(addr.align_up(8), 8);
        assert_eq!(addr.align_up(16), 16);
        assert_eq!(addr.align_up(32), 32);

        let addr = 127u32;
        assert_eq!(addr.align_up(1), 127);
        assert_eq!(addr.align_up(2), 128);
        assert_eq!(addr.align_up(4), 128);
        assert_eq!(addr.align_up(8), 128);
        assert_eq!(addr.align_up(16), 128);
        assert_eq!(addr.align_up(32), 128);

        let addr = 130u32;
        assert_eq!(addr.align_up(1), 130);
        assert_eq!(addr.align_up(2), 130);
        assert_eq!(addr.align_up(4), 132);
        assert_eq!(addr.align_up(8), 136);
        assert_eq!(addr.align_up(16), 144);
        assert_eq!(addr.align_up(32), 160);
    }
}
