#![feature(core_intrinsics)]
#![cfg_attr(test, feature(test))]

extern crate typenum;

pub mod array;
pub mod cipher;
pub mod keyed;
pub mod secret;
pub mod permutation;

mod utils;
