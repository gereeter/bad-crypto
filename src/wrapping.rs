use std::ops::{Add, Sub};

pub struct Wrapping<T>(pub T);

impl<Lhs: WrappingAdd<Rhs>, Rhs> Add<Wrapping<Rhs>> for Wrapping<Lhs> {
    type Output = Wrapping<<Lhs as WrappingAdd<Rhs>>::Output>;
    fn add(self, rhs: Wrapping<Rhs>) -> Self::Output {
        Wrapping(self.0.wrapping_add(rhs.0))
    }
}

impl<Lhs: WrappingSub<Rhs>, Rhs> Sub<Wrapping<Rhs>> for Wrapping<Lhs> {
    type Output = Wrapping<<Lhs as WrappingSub<Rhs>>::Output>;
    fn sub(self, rhs: Wrapping<Rhs>) -> Self::Output {
        Wrapping(self.0.wrapping_sub(rhs.0))
    }
}

pub trait WrappingAdd<Rhs> {
    type Output;
    fn wrapping_add(self, rhs: Rhs) -> Self::Output;
}

pub trait WrappingSub<Rhs> {
    type Output;
    fn wrapping_sub(self, rhs: Rhs) -> Self::Output;
}

macro_rules! pod_impl {
    { $t:ty } => {
        impl WrappingAdd<$t> for $t {
            type Output = $t;
            fn wrapping_add(self, rhs: $t) -> $t {
                self.wrapping_add(rhs)
            }
        }

        impl WrappingSub<$t> for $t {
            type Output = $t;
            fn wrapping_sub(self, rhs: $t) -> $t {
                self.wrapping_sub(rhs)
            }
        }
    };
}

pod_impl! { u8 }
pod_impl! { u16 }
pod_impl! { u32 }
pod_impl! { u64 }
pod_impl! { usize }
pod_impl! { i8 }
pod_impl! { i16 }
pod_impl! { i32 }
pod_impl! { i64 }
pod_impl! { isize }

#[cfg(test)]
mod tests {
    use super::{WrappingAdd, WrappingSub};

    #[test]
    fn no_loop() {
        assert_eq!(WrappingAdd::wrapping_add(0u8, 0u8), 0);
        assert_eq!(WrappingAdd::wrapping_add(0u16, 0u16), 0);
        assert_eq!(WrappingAdd::wrapping_add(0u32, 0u32), 0);
        assert_eq!(WrappingAdd::wrapping_add(0u64, 0u64), 0);
        assert_eq!(WrappingAdd::wrapping_add(0usize, 0usize), 0);
        assert_eq!(WrappingAdd::wrapping_add(0i8, 0i8), 0);
        assert_eq!(WrappingAdd::wrapping_add(0i16, 0i16), 0);
        assert_eq!(WrappingAdd::wrapping_add(0i32, 0i32), 0);
        assert_eq!(WrappingAdd::wrapping_add(0i64, 0i64), 0);
        assert_eq!(WrappingAdd::wrapping_add(0isize, 0isize), 0);

        assert_eq!(WrappingSub::wrapping_sub(0u8, 0u8), 0);
        assert_eq!(WrappingSub::wrapping_sub(0u16, 0u16), 0);
        assert_eq!(WrappingSub::wrapping_sub(0u32, 0u32), 0);
        assert_eq!(WrappingSub::wrapping_sub(0u64, 0u64), 0);
        assert_eq!(WrappingSub::wrapping_sub(0usize, 0usize), 0);
        assert_eq!(WrappingSub::wrapping_sub(0i8, 0i8), 0);
        assert_eq!(WrappingSub::wrapping_sub(0i16, 0i16), 0);
        assert_eq!(WrappingSub::wrapping_sub(0i32, 0i32), 0);
        assert_eq!(WrappingSub::wrapping_sub(0i64, 0i64), 0);
        assert_eq!(WrappingSub::wrapping_sub(0isize, 0isize), 0);
    }
}
