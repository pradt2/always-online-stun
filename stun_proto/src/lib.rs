#![no_std]

extern crate alloc;

mod reader;
mod endian;
pub mod byte;
mod attrs;
mod msg;
mod raw;
mod repr_c;
mod typed;

use reader::*;
use attrs::*;
use msg::*;

pub mod rfc3489;
pub mod rfc5389;