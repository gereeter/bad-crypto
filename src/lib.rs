#![feature(core_intrinsics, op_assign_traits, augmented_assignments)]

extern crate typenum;

pub mod array;
pub mod cipher;
pub mod keyed;
pub mod secret;

mod wrapping;
mod nodrop;
mod truncate;
mod signs;
