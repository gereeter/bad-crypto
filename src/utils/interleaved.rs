use std::ops::{BitAnd, BitOr, BitXor};

use utils::traits::rotate::{RotateRight, RotateLeft};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Interleaved<T> {
    evens: T,
    odds: T
}

impl<T: RotateLeft<u32>> RotateLeft<u32> for Interleaved<T> {
    type Output = Interleaved<<T as RotateLeft<u32>>::Output>;
    fn rotate_left(self, rhs: u32) -> Self::Output {
        if rhs & 1 == 0 {
            Interleaved {
                evens: self.evens.rotate_left(rhs >> 1),
                odds: self.odds.rotate_left(rhs >> 1)
            }
        } else {
            Interleaved {
                evens: self.odds.rotate_left(1 + (rhs >> 1)),
                odds: self.evens.rotate_left(rhs >> 1)
            }
        }
    }
}

impl<T: RotateRight<u32>> RotateRight<u32> for Interleaved<T> {
    type Output = Interleaved<<T as RotateRight<u32>>::Output>;
    fn rotate_right(self, rhs: u32) -> Self::Output {
        if rhs & 1 == 0 {
            Interleaved {
                evens: self.evens.rotate_right(rhs >> 1),
                odds: self.odds.rotate_right(rhs >> 1)
            }
        } else {
            Interleaved {
                evens: self.odds.rotate_right(rhs >> 1),
                odds: self.evens.rotate_right(1 + (rhs >> 1))
            }
        }
    }
}

macro_rules! bitwise_impl {
    { $tr:ident, $method:ident } => {
        impl<T: $tr<U>, U> $tr<Interleaved<U>> for Interleaved<T> {
            type Output = Interleaved<<T as $tr<U>>::Output>;
            fn $method(self, rhs: Interleaved<U>) -> Self::Output {
                Interleaved {
                    evens: $tr::$method(self.evens, rhs.evens),
                    odds: $tr::$method(self.odds, rhs.odds)
                }
            }
        }
    }
}

bitwise_impl!{ BitAnd, bitand }
bitwise_impl!{ BitOr, bitor }
bitwise_impl!{ BitXor, bitxor }

