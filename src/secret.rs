use std::ops::{Not, BitAnd, BitOr, BitXor, Add, Sub};
use std::num::Wrapping;

/// A type designating data that will only be used in a constant time manner
pub struct Secret<T: Copy> {
    inner: T
}

impl<T: Copy> Secret<T> {
    pub fn new(val: T) -> Secret<T> {
        Secret { inner: val }
    }

    /// Expose the data inside this wrapper. TODO: warning about use and greppability
    pub fn expose(self) -> T {
        self.inner
    }
}

macro_rules! pod_impl {
    { $tr:ident, $method:ident, $t:ty } => {
        impl $tr<$t> for Secret<$t> {
            type Output = Secret<<$t as $tr<$t>>::Output>;
            fn $method(self, rhs: $t) -> Self::Output {
                Secret::new($tr::$method(self.expose(), rhs))
            }
        }

        impl $tr<Secret<$t>> for $t {
            type Output = Secret<<$t as $tr<$t>>::Output>;
            fn $method(self, rhs: Secret<$t>) -> Self::Output {
                Secret::new($tr::$method(self, rhs.expose()))
            }
        }

        impl $tr<Secret<$t>> for Secret<$t> {
            type Output = Secret<<$t as $tr<$t>>::Output>;
            fn $method(self, rhs: Secret<$t>) -> Self::Output {
                Secret::new($tr::$method(self.expose(), rhs.expose()))
            }
        }
    };
}

macro_rules! pod_impls {
    { $t:ty } => {
        impl Not for Secret<$t> {
            type Output = Secret<<$t as Not>::Output>;
            fn not(self) -> Self::Output {
                Secret::new(!self.expose())
            }
        }

        pod_impl! { BitAnd, bitand, $t }
        pod_impl! { BitOr, bitor, $t }
        pod_impl! { BitXor, bitxor, $t }
        pod_impl! { Add, add, Wrapping<$t> }
        pod_impl! { Sub, sub, Wrapping<$t> }
    };
}

pod_impls! { u8 }
pod_impls! { u16 }
pod_impls! { u32 }
pod_impls! { u64 }
pod_impls! { usize }
pod_impls! { i8 }
pod_impls! { i16 }
pod_impls! { i32 }
pod_impls! { i64 }
pod_impls! { isize }
