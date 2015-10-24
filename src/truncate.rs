pub trait Truncate<T> {
    fn truncate(self) -> T;
}

macro_rules! pod_impls {
    { $t:ty } => { };
    { $t:ty, $($rest:ty),* } => {
        pod_impls! { $($rest),* }

        $(
        impl Truncate<$rest> for $t {
            fn truncate(self) -> $rest {
                self as $rest
            }
        }
        )*
    };
}

pod_impls! { u64, u32, u16, u8 }
pod_impls! { i64, i32, i16, i8 }
