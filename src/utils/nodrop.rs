use std::intrinsics;
use std::mem;
use std::ops::{Deref, DerefMut};

pub struct NoDrop<T> {
    inner: Option<T>
}

impl<T> Drop for NoDrop<T> {
    fn drop(&mut self) {
        mem::forget(self.inner.take());
    }
}

impl<T> Deref for NoDrop<T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self.inner {
            Some(ref val) => val,
            None => unsafe { intrinsics::unreachable() }
        }
    }
}

impl<T> DerefMut for NoDrop<T> {
    fn deref_mut(&mut self) -> &mut T {
        match self.inner {
            Some(ref mut val) => val,
            None => unsafe { intrinsics::unreachable() }
        }
    }
}

impl<T> NoDrop<T> {
    pub fn new(val: T) -> NoDrop<T> {
        NoDrop {
            inner: Some(val)
        }
    }

    pub fn into_inner(mut self) -> T {
        match self.inner.take() {
            Some(val) => val,
            None => unsafe { intrinsics::unreachable() }
        }
    }
}
