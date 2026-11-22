//! NT Memory Manager (Mm)
//! Manages Physical Memory (PMM), Dynamic Kernel Pool (NonPagedPool),
//! Virtual Memory Paging (VMM), and Virtual Memory System Calls.

pub mod api;
pub mod pmm;
pub mod pool;
pub mod vmm;

pub use api::*;
pub use pmm::*;
pub use pool::*;
pub use vmm::*;
