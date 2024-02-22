use crate::report::SourceId;

pub trait HasSpan {
    /// Returns the starting and ending position within the source code for
    /// some node in the AST.
    fn span(&self) -> Span;
}

/// Span indicates the starting and ending position for some node in the AST.
///
/// Positions are absolute byte offsets within the original source code.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Default)]
pub struct Span {
    /// The [`SourceId`] associated to the source file that contains this span.
    source_id: SourceId,
    /// Starting byte offset.
    start: usize,
    /// Ending byte offset, exclusive.
    end: usize,
}

impl Span {
    pub fn new(source_id: SourceId, start: usize, end: usize) -> Self {
        Self { source_id, start, end }
    }

    /// [`SourceId`] associated to the source file that contains this span.
    #[inline]
    pub fn source_id(&self) -> SourceId {
        self.source_id
    }

    /// Byte offset where the span starts.
    #[inline]
    pub fn start(&self) -> usize {
        self.start
    }

    /// Byte offset where the span ends.
    #[inline]
    pub fn end(&self) -> usize {
        self.end
    }

    /// Returns a new span that combines this span with `other`.
    ///
    /// The resulting span goes from `self.start()` to `other.end()`.
    pub fn combine(&self, other: &Span) -> Span {
        assert_eq!(self.source_id, other.source_id);
        Span { source_id: self.source_id, start: self.start, end: other.end }
    }

    /// Returns a new [`Span`] that is a subspan of the original one.
    ///
    /// `start` and `end` are the starting and ending offset of the subspan,
    /// relative to the start of the original span.
    pub fn subspan(&self, start: usize, end: usize) -> Span {
        assert!(start <= self.end - self.start);
        assert!(end <= self.end - self.start);
        Span {
            source_id: self.source_id,
            start: self.start + start,
            end: self.start + end,
        }
    }
}
