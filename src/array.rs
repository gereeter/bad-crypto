use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut, Add};
use std::ptr;
use std::slice;

use typenum::bit::{B0, B1};
use typenum::consts::{U0, U1};
use typenum::uint::{Unsigned, UInt, UTerm};

pub struct Array<T, Len: ArrayLength<T>> {
    data: Len::Array,
    _marker: PhantomData<T>
}

impl<T, Len: ArrayLength<T>> Deref for Array<T, Len> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe {
            slice::from_raw_parts(
                &self.data as *const _ as *const T,
                Len::to_usize()
            )
        }
    }
}

impl<T, Len: ArrayLength<T>> DerefMut for Array<T, Len> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe {
            slice::from_raw_parts_mut(
                &mut self.data as *mut _ as *mut T,
                Len::to_usize()
            )
        }
    }
}

impl<T> Array<T, U0> {
    pub fn new() -> Array<T, U0> {
        Array {
            data: (),
            _marker: PhantomData
        }
    }
}

impl<T, Len: ArrayLength<T>> Array<T, Len> {
    pub fn push(self, val: T) -> Array<T, <Len as Add<U1>>::Output>
            where Len: Add<U1>, <Len as Add<U1>>::Output: ArrayLength<T> {
        unsafe {
            let mut output = Array {
                data: mem::uninitialized(),
                _marker: PhantomData
            };

            ptr::copy_nonoverlapping(
                self.as_ptr(),
                output.as_mut_ptr(),
                self.len()
            );
            ptr::write(output.get_unchecked_mut(self.len()), val);

            mem::forget(self);

            output
        }
    }

    pub fn append<OtherLen: ArrayLength<T>>(self, other: Array<T, OtherLen>) -> Array<T, <Len as Add<OtherLen>>::Output>
            where Len: Add<OtherLen>, <Len as Add<OtherLen>>::Output: ArrayLength<T> {
        unsafe {
            let mut output = Array {
                data: mem::uninitialized(),
                _marker: PhantomData
            };

            ptr::copy_nonoverlapping(
                self.as_ptr(),
                output.as_mut_ptr(),
                self.len()
            );
            ptr::copy_nonoverlapping(
                other.as_ptr(),
                output.as_mut_ptr().offset(self.len() as isize),
                other.len()
            );

            mem::forget(self);
            mem::forget(other);

            output
        }
    }
}

pub unsafe trait ArrayLength<T>: Unsigned {
    type Array;
}

unsafe impl<T> ArrayLength<T> for UTerm {
    type Array = ();
}

#[repr(C)]
pub struct InternalX0Array<T, X: ArrayLength<T>> {
    _one: X::Array,
    _two: X::Array,
    _marker: PhantomData<T>
}

unsafe impl<T, X: ArrayLength<T>> ArrayLength<T> for UInt<X, B0> {
    type Array = InternalX0Array<T, X>;
}

#[repr(C)]
pub struct InternalX1Array<T, X: ArrayLength<T>> {
    _one: X::Array,
    _two: X::Array,
    _three: T
}

unsafe impl<T, X: ArrayLength<T>> ArrayLength<T> for UInt<X, B1> {
    type Array = InternalX1Array<T, X>;
}

#[cfg(test)]
mod tests {
    use super::Array;

    #[test]
    fn test_push() {
        let arr = Array::new().push(1).push(2).push(3).push(4).push(5);
        assert_eq!(&*arr, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_append() {
        let arr1 = Array::new().push(1).push(2).push(3);
        let arr2 = Array::new().push(4).push(5);
        assert_eq!(&*arr1.append(arr2), [1, 2, 3, 4, 5]);
    }
}
