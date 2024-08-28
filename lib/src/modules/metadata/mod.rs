use crate::modules::prelude::*;
use crate::modules::protos::metadata::*;
use crate::scanner::ScanInputRaw;

#[cfg(test)]
mod tests;

mod utils;

mod arpot;
mod detection;
mod idp;
mod name;
mod parent_process;
mod source;

#[module_main]
fn main(data: &ScanInputRaw) -> Metadata {
    let parsed = serde_json::from_slice::<serde_json::Value>(
        data.meta.unwrap_or_default(),
    )
    // on error, returns `Null` json, which should result in "error" (`Null` return) in all the functions
    // -> intended behavior
    .unwrap_or_default();

    let mut res = Metadata::new();
    res.set_json(parsed.to_string());
    res
}
