#![feature(core_intrinsics, op_assign_traits, augmented_assignments)]
#![cfg_attr(test, feature(test))]

extern crate typenum;

pub mod array;
pub mod cipher;
pub mod keyed;
pub mod secret;

mod rotate;
mod wrapping;
mod nodrop;
mod truncate;
mod signs;
