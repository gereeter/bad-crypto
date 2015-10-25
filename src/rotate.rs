pub trait RotateLeft<Rhs> {
    type Output;
    fn rotate_left(self, rhs: Rhs) -> Self::Output;
}

pub trait RotateRight<Rhs> {
    type Output;
    fn rotate_right(self, rhs: Rhs) -> Self::Output;
}

macro_rules! pod_impls {
    { $t:ty } => {
        impl RotateLeft<u32> for $t {
            type Output = $t;
            fn rotate_left(self, rhs: u32) -> $t {
                self.rotate_left(rhs)
            }
        }

        impl RotateRight<u32> for $t {
            type Output = $t;
            fn rotate_right(self, rhs: u32) -> $t {
                self.rotate_right(rhs)
            }
        }
    };

    { $t:ty, $($rest:ty),* } => {
        pod_impls! { $t }
        pod_impls! { $($rest),* }
    };
}

pod_impls! { u8, u16, u32, u64, i8, i16, i32, i64 }
