use std::ops::{Not, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, ShlAssign, Shr, ShrAssign};
use wrapping::{WrappingAdd, WrappingSub};

/// A type designating data that will only be used in a constant time manner
pub struct Secret<T: Copy> {
    inner: T
}

impl<T: Copy> Copy for Secret<T> { }
impl<T: Copy> Clone for Secret<T> {
    fn clone(&self) -> Secret<T> {
        *self
    }
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

    { $tr:ident, $method:ident, $trassign:ident, $methodassign: ident, $t:ty } => {
        pod_impl! { $tr, $method, $t }

        impl $trassign<Secret<$t>> for Secret<$t> {
            fn $methodassign(&mut self, rhs: Secret<$t>) {
                $trassign::$methodassign(&mut self.inner, rhs.expose());
            }
        }

        impl $trassign<$t> for Secret<$t> {
            fn $methodassign(&mut self, rhs: $t) {
                $trassign::$methodassign(&mut self.inner, rhs);
            }
        }
    };

    { shift, $tr:ident, $method:ident, $trassign:ident, $methodassign: ident, $t:ty } => {
        impl $tr<usize> for Secret<$t> {
            type Output = Secret<<$t as $tr<$t>>::Output>;
            fn $method(self, rhs: usize) -> Self::Output {
                Secret::new($tr::$method(self.expose(), rhs))
            }
        }

        impl $trassign<usize> for Secret<$t> {
            fn $methodassign(&mut self, rhs: usize) {
                $trassign::$methodassign(&mut self.inner, rhs);
            }
        }
    }
}

macro_rules! pod_impls {
    { $t:ty } => {
        impl Not for Secret<$t> {
            type Output = Secret<<$t as Not>::Output>;
            fn not(self) -> Self::Output {
                Secret::new(!self.expose())
            }
        }

        pod_impl! { BitAnd, bitand, BitAndAssign, bitand_assign, $t }
        pod_impl! { BitOr, bitor, BitOrAssign, bitor_assign, $t }
        pod_impl! { BitXor, bitxor, BitXorAssign, bitxor_assign, $t }
        pod_impl! { shift, Shl, shl, ShlAssign, shl_assign, $t }
        pod_impl! { shift, Shr, shr, ShrAssign, shr_assign, $t }
        pod_impl! { WrappingAdd, wrapping_add, $t }
        pod_impl! { WrappingSub, wrapping_sub, $t }
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
