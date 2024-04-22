use std::collections::{HashMap, HashSet};

use yara_parser::SyntaxToken;

/// A structure that holds information about the parsing process.
pub(crate) struct Context {
    /// Contains the pattern identifiers declared by the rule that is being
    /// currently parsed. The map is filled during the processing of the
    /// patterns (a.k.a: strings) section of the rule. Identifiers are stored
    /// without the `$` prefix.
    pub(crate) declared_patterns: HashMap<String, SyntaxToken>,

    /// Similarly to `declared_patterns` this is filled with the identifiers
    /// of the patterns declared by the current rule. However, during the
    /// parsing of the rule's condition, identifiers are removed from this
    /// set as they are used in the condition.
    ///
    /// For example, if `$a` appears in the condition, `a` is removed from
    /// this set, if `them` appears, all identifiers are removed because this
    /// keyword refers to all of the identifiers, if a tuple (`$a*`, `$b*`)
    /// appears in the condition, all identifiers starting with `a` and `b`
    /// are removed.
    ///
    /// After the whole condition is parsed, the remaining identifiers are
    /// the unused ones.
    pub(crate) unused_patterns: HashSet<String>,

    /// While parsing a pattern declaration this holds its identifier.
    #[allow(dead_code)]
    pub(crate) current_pattern: Option<SyntaxToken>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            declared_patterns: HashMap::new(),
            unused_patterns: HashSet::new(),
            current_pattern: None,
        }
    }

    /// Returns the identifier of the pattern that is currently being parsed.
    ///
    /// # Panics
    ///
    /// Panics if called at some point where a pattern is not being parsed
    pub(crate) fn _current_pattern_ident(&self) -> String {
        self.current_pattern.as_ref().unwrap().text().to_string()
    }
}
