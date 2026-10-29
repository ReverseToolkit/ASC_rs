//! HarmonyOS HAP access.
//!
//! `.abc` members are discovered from the ZIP central directory and inflated
//! only when a command needs them.

#[macro_use]
mod error;
mod hap;
mod resources;

pub use error::{Error, Result};
pub use hap::{
    dump_abc, dump_abc_with_mode, dump_hap, dump_hap_with_mode, find_refs, get_class_output,
    get_class_source, is_hap, list_classes, load_resources, module_json, DumpStats, Options, Query,
};
pub use resources::HapResources;
