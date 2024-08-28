#[derive(serde::Deserialize)]
pub(super) struct Detection {
    pub av: String,
    pub names: Vec<String>,
}
#[derive(serde::Deserialize)]
pub(super) struct Arpot {
    pub processes: Vec<String>,
    pub dlls: Vec<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct Idp {
    pub rules: Vec<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct ParentProcess {
    pub paths: Vec<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct Source {
    pub urls: Vec<String>,
}

/// schema of the json file that is expected to be used in this module
///
/// serves as a template for the serde deserialization and for type-safe access to the fields
#[derive(serde::Deserialize)]
pub(super) struct MetaJson {
    pub file_names: Vec<String>,
    pub detections: Vec<Detection>,
    pub arpot: Arpot,
    pub idp: Idp,
    pub parent_process: ParentProcess,
    pub source: Source,
}
