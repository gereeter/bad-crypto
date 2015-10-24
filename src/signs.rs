pub trait ToSigned: Sized {
    type Output: ToUnsigned<Output=Self>;
    fn to_signed(self) -> Self::Output;
}

pub trait ToUnsigned: Sized {
    type Output: ToSigned<Output=Self>;
    fn to_unsigned(self) -> Self::Output;
}

macro_rules! pod_impl {
    { $u:ty, $i: ty } => {
        impl ToSigned for $u {
            type Output = $i;
            fn to_signed(self) -> $i {
                self as $i
            }
        }

        impl ToUnsigned for $i {
            type Output = $u;
            fn to_unsigned(self) -> $u {
                self as $u
            }
        }
    };
}

pod_impl! { u8, i8 }
pod_impl! { u16, i16 }
pod_impl! { u32, i32 }
pod_impl! { u64, i64 }
