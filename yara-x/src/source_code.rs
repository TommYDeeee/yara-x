use bstr::{BStr, ByteSlice};

/// A structure that describes some YARA source code.
///
/// This structure contains a `&str` pointing to the code itself, and an
/// optional `origin` that tells where the source code came from. The
/// most common use for `origin` is indicating the path of the file from
/// where the source code was obtained, but it can contain any arbitrary
/// string. This string, if provided, will appear in error messages. For
/// example, in this error message `origin` was set to `some_file.yar`:
///
/// ```text
/// error: syntax error
///    ╭─[some_file.yar:8:6]
///    │
///    ... more details
/// ```
///
/// # Example
///
/// ```
/// use yara_x_parser::SourceCode;
/// let src = SourceCode::from("rule test { condition: true }").with_origin("some_file.yar");
/// ```
///
#[derive(Debug, Clone)]
pub struct SourceCode<'src> {
    /// A reference to the source code itself. This is a BStr because the
    /// source code could contain non-UTF8 content.
    pub(crate) raw: &'src BStr,
    /// A reference to the source code after validating that it is valid
    /// UTF-8.
    pub(crate) valid: Option<&'src str>,
    /// An optional string that tells which is the origin of the code. Usually
    /// a file path.
    pub(crate) origin: Option<String>,
}

impl<'src> SourceCode<'src> {
    /// Sets a string that describes the origin of the source code.
    ///
    /// This is usually the path of the file that contained the source code
    /// but it can be an arbitrary string. The origin appears in error and
    /// warning messages.
    pub fn with_origin(self, origin: &str) -> Self {
        Self {
            raw: self.raw,
            valid: self.valid,
            origin: Some(origin.to_owned()),
        }
    }

    /// Make sure that the source code is valid UTF-8. If that's the case
    /// sets the `valid` field, if not, returns an error.
    pub fn validate_utf8(&mut self) -> Result<(), bstr::Utf8Error> {
        if self.valid.is_none() {
            self.valid = Some(self.raw.to_str()?);
        }
        Ok(())
    }
}

impl<'src> From<&'src str> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&str`.
    fn from(src: &'src str) -> Self {
        // The input is a &str, therefore it's guaranteed to be valid UTF-8
        // and the `valid` field can initialized.
        Self { raw: BStr::new(src), valid: Some(src), origin: None }
    }
}

impl<'src> From<&'src [u8]> for SourceCode<'src> {
    /// Creates a new [`SourceCode`] from a `&[u8]`.
    ///
    /// As `src` is not guaranteed to be a valid UTF-8 string, the parser will
    /// verify it and return an error if invalid UTF-8 characters are found.
    fn from(src: &'src [u8]) -> Self {
        // The input is a &[u8], its content is not guaranteed to be valid
        // UTF-8 so the `valid` field is set to `None`. The `validate_utf8`
        // function will be called for validating the source code before
        // being parsed.
        Self { raw: BStr::new(src), valid: None, origin: None }
    }
}
