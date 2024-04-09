/*! Functions for converting an AST into an IR. */

use num_traits::{Bounded, CheckedMul, FromPrimitive, Num};
use std::borrow::{Borrow, Cow};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::rc::Rc;
use std::{iter, string};

use crate::report::{ReportBuilder, SourceId};
use crate::span::{HasSpan, Span};
use crate::warnings::{self, Warning};
use bstr::{BStr, BString, ByteSlice, ByteVec};
use itertools::Itertools;
use serde_json::value;
use yara_parser::AstToken;
use yara_parser::{AstNode, SyntaxToken, XorRange};
use yara_x_parser::{ast, ErrorInfo};

use crate::compiler::ir::hex2hir::hex_pattern_hir_from_ast;
use crate::compiler::ir::{
    Context, Expr, ForIn, ForOf, FuncCall, Iterable, LiteralPattern, Lookup,
    MatchAnchor, Of, OfItems, Pattern, PatternFlagSet, PatternFlags,
    PatternIdx, PatternInRule, Quantifier, Range, RegexpPattern,
};
use crate::compiler::{CompileContext, CompileError};
use crate::modules::BUILTIN_MODULES;
use crate::re;
use crate::re::parser::Error;
use crate::symbols::{Symbol, SymbolKind, SymbolLookup, SymbolTable};
use crate::types::{Map, Regexp, Type, TypeValue, Value};

pub fn string_lit_from_cst(
    report_builder: &ReportBuilder,
    token: SyntaxToken,
    allow_escape_char: bool,
) -> Result<BString, Box<CompileError>> {
    let literal = token.text();
    // The string literal must be enclosed in double quotes.
    debug_assert!(literal.starts_with('\"'));
    debug_assert!(literal.ends_with('\"'));

    // From now on ignore the quotes.
    let literal = &literal[1..literal.len() - 1];

    // Check if the string contains some backslash.
    let backslash_pos = if let Some(backslash_pos) = literal.find('\\') {
        if !allow_escape_char {
            return Err(Box::new(CompileError::unexpected_escape_sequence(
                report_builder,
                Span::new(
                    SourceId(0),
                    token.text_range().start().into(),
                    token.text_range().end().into(),
                ),
            )));
        }
        backslash_pos
    } else {
        // If the literal does not contain a backslash it can't contain escaped
        // characters, the literal is exactly as it appears in the source code.
        // Therefore, we can return a reference to it in the form of a &BStr,
        // allocating a new BString is not necessary.
        return Ok(BString::from(literal));
    };

    // Initially the result is a copy of the literal string up to the first
    // backslash found.
    let mut result = BString::from(&literal[..backslash_pos]);

    // Process the remaining part of the literal, starting at the backslash.
    let literal = &literal[backslash_pos..];
    let mut chars = literal.char_indices();

    while let Some((backslash_pos, b)) = chars.next() {
        match b {
            // The backslash indicates an escape sequence.
            '\\' => {
                // Consume the backslash and see what's next. A character must
                // follow the backslash, this is guaranteed by the grammar
                // itself.
                let escaped_char = chars.next().unwrap();

                match escaped_char.1 {
                    '\\' => result.push(b'\\'),
                    'n' => result.push(b'\n'),
                    'r' => result.push(b'\r'),
                    't' => result.push(b'\t'),
                    '0' => result.push(b'\0'),
                    '"' => result.push(b'"'),
                    'x' => match (chars.next(), chars.next()) {
                        (Some((start, _)), Some((end, _))) => {
                            if let Ok(hex_value) =
                                u8::from_str_radix(&literal[start..=end], 16)
                            {
                                result.push(hex_value);
                            } else {
                                return Err(Box::new(
                                    CompileError::invalid_escape_sequence(
                                        report_builder,
                                        format!(
                                            r"invalid hex value `{}` after `\x`",
                                            &literal[start..=end]
                                        ),
                                        Span::new(
                                            SourceId(0),
                                            token.text_range().start().into(),
                                            token.text_range().end().into(),
                                        ),
                                    ),
                                ));
                            }
                        }
                        _ => {
                            return Err(Box::new(
                                CompileError::invalid_escape_sequence(
                                    report_builder,
                                    r"expecting two hex digits after `\x`"
                                        .to_string(),
                                    Span::new(
                                        SourceId(0),
                                        token.text_range().start().into(),
                                        token.text_range().end().into(),
                                    ),
                                ),
                            ));
                        }
                    },
                    _ => {
                        let (escaped_char_pos, escaped_char) = escaped_char;

                        let escaped_char_end_pos =
                            escaped_char_pos + escaped_char.len_utf8();

                        return Err(Box::new(
                            CompileError::invalid_escape_sequence(
                                report_builder,
                                format!(
                                    "invalid escape sequence `{}`",
                                    &literal
                                        [backslash_pos..escaped_char_end_pos]
                                ),
                                Span::new(
                                    SourceId(0),
                                    token.text_range().start().into(),
                                    token.text_range().end().into(),
                                ),
                            ),
                        ));
                    }
                }
            }
            // Non-escaped characters are copied as is.
            c => result.push_char(c),
        }
    }

    Ok(result)
}

pub fn integer_lit_from_cst<T>(
    report_builder: &ReportBuilder,
    token: SyntaxToken,
) -> Result<T, Box<CompileError>>
where
    T: Num + Bounded + CheckedMul + FromPrimitive + std::fmt::Display,
{
    let mut literal = token.text();
    let mut multiplier = 1;

    if let Some(without_suffix) = literal.strip_suffix("KB") {
        literal = without_suffix;
        multiplier = 1024;
    }

    if let Some(without_suffix) = literal.strip_suffix("MB") {
        literal = without_suffix;
        multiplier = 1024 * 1024;
    }

    if let Some(without_sign) = literal.strip_prefix('-') {
        literal = without_sign;
        multiplier = -multiplier;
    }

    let value = if literal.starts_with("0x") {
        T::from_str_radix(literal.strip_prefix("0x").unwrap(), 16)
    } else if literal.starts_with("0o") {
        T::from_str_radix(literal.strip_prefix("0o").unwrap(), 8)
    } else {
        T::from_str_radix(literal, 10)
    };

    let build_error = || {
        Box::new(CompileError::invalid_integer(
            report_builder,
            format!(
                "this number is out of the valid range: [{}, {}]",
                T::min_value(),
                T::max_value()
            ),
            Span::new(
                SourceId(0),
                token.text_range().start().into(),
                token.text_range().end().into(),
            ),
        ))
    };

    // Report errors that occur while parsing the literal. Some errors
    // (like invalid characters or empty literals) never occur, because
    // the grammar ensures that only valid integers reach this point,
    // however the grammar doesn't make sure that the integer fits in
    // type T.
    let value = value.map_err(|_| build_error())?;

    let multiplier = T::from_i32(multiplier).ok_or_else(|| build_error())?;

    let value = value.checked_mul(&multiplier).ok_or_else(|| build_error())?;

    Ok(value)
}

fn float_lit_from_cst<'src>(
    report_builder: &ReportBuilder,
    token: SyntaxToken,
) -> Result<f64, Box<CompileError>> {
    let literal = token.text();
    literal.parse::<f64>().map_err(|err| {
        Box::new(CompileError::invalid_float(
            report_builder,
            err.to_string(),
            Span::new(
                SourceId(0),
                token.text_range().start().into(),
                token.text_range().end().into(),
            ),
        ))
    })
}

pub(in crate::compiler) fn pattern_from_ast(
    parse_context: &mut Context,
    warnings: &mut Vec<Warning>,
    report_builder: &ReportBuilder,
    pattern: yara_parser::VariableStmt,
) -> Result<PatternInRule, Box<CompileError>> {
    let identifier = pattern.variable_token().unwrap().text().to_string();

    if identifier != "$" {
        if let Some(existing_pattern_ident) =
            parse_context.declared_patterns.get(&identifier[1..])
        {
            return Err(Box::new(CompileError::duplicate_pattern(
                report_builder,
                identifier,
                Span::new(
                    SourceId(0),
                    pattern
                        .variable_token()
                        .unwrap()
                        .text_range()
                        .start()
                        .into(),
                    pattern
                        .variable_token()
                        .unwrap()
                        .text_range()
                        .end()
                        .into(),
                ),
                Span::new(
                    SourceId(0),
                    existing_pattern_ident.text_range().start().into(),
                    existing_pattern_ident.text_range().end().into(),
                ),
            )));
        }
    }

    parse_context.unused_patterns.insert(identifier[1..].to_owned());

    parse_context
        .declared_patterns
        .insert(identifier[1..].to_owned(), pattern.variable_token().unwrap());

    let pattern_token = pattern.pattern().unwrap();
    if pattern_token.string_lit_token().is_some() {
        text_pattern_from_ast(report_builder, pattern)
    } else if pattern_token.hex_pattern().is_some() {
        hex_pattern_from_ast(warnings, report_builder, pattern)
    } else {
        regex_pattern_from_ast(report_builder, pattern)
    }
}

fn text_pattern_from_ast(
    report_builder: &ReportBuilder,
    pattern: yara_parser::VariableStmt,
) -> Result<PatternInRule, Box<CompileError>> {
    let mut flags = PatternFlagSet::none();

    let identifier = pattern.variable_token().unwrap().text().to_string();
    let string_pattern = pattern.pattern().unwrap();
    let binding = string_pattern.string_lit_token().unwrap();

    //Pattern modifiers
    let mut modifiers = BTreeMap::new();
    let mut base64_alphabet = None;
    let mut base64wide_alphabet = None;
    let mut xor_range = None;

    // Set default ascii flag for empty modifiers
    if string_pattern.pattern_mods().next().is_none() {
        flags.set(PatternFlags::Ascii);
    }

    for modifier in string_pattern.pattern_mods() {
        // Check if there are no duplicates in modifiers
        if modifiers
            .insert(
                modifier
                    .syntax()
                    .first_child_or_token()
                    .unwrap()
                    .into_token()
                    .unwrap()
                    .text()
                    .to_string(),
                modifier.clone(),
            )
            .is_some()
        {
            return Err(Box::new(CompileError::duplicate_modifier(
                report_builder,
                Span::new(
                    SourceId(0),
                    modifier.syntax().text_range().start().into(),
                    modifier.syntax().text_range().end().into(),
                ),
            )));
        }

        if modifier.ascii_token().is_some() || modifier.wide_token().is_none()
        {
            flags.set(PatternFlags::Ascii);
        }

        if modifier.wide_token().is_some() {
            flags.set(PatternFlags::Wide);
        }

        if modifier.fullword_token().is_some() {
            flags.set(PatternFlags::Fullword);
        }

        if modifier.nocase_token().is_some() {
            flags.set(PatternFlags::Nocase);
        }

        if modifier.base64_token().is_some()
            || modifier.base64wide_token().is_some()
        {
            if let Some(base64alphabet) = modifier.base_alphabet() {
                match validate_base64_alphabet(base64alphabet, report_builder)
                {
                    Ok(alphabet_str) => {
                        if modifier.base64_token().is_some() {
                            base64_alphabet = Some(alphabet_str);
                        } else {
                            base64wide_alphabet = Some(alphabet_str);
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            if modifier.base64_token().is_some() {
                flags.set(PatternFlags::Base64);
            } else {
                flags.set(PatternFlags::Base64Wide);
            }
        }

        if modifier.xor_token().is_some() {
            let (lower_bound, upper_bound) =
                validate_xor(modifier, report_builder)?;
            flags.set(PatternFlags::Xor);
            xor_range = Some(lower_bound..=upper_bound)
        }

        // private flag is not supported on compiler level yet
    }

    validate_pattern_modifiers(&modifiers, report_builder)?;

    // Check minimum length
    let (min_len, note) = if modifiers.get("base64").is_some() {
        (
            3,
            Some(
                "`base64` requires that pattern is at least 3 bytes long"
                    .to_string(),
            ),
        )
    } else if modifiers.get("base64wide").is_some() {
        (
            3,
            Some(
                "`base64wide` requires that pattern is at least 3 bytes long"
                    .to_string(),
            ),
        )
    } else {
        (1, None)
    };

    let text = bstr::BString::from(string_lit_from_cst(
        report_builder,
        binding,
        true,
    )?); //use better string validation
    if text.len() < min_len {
        return Err(Box::new(CompileError::invalid_pattern(
            report_builder,
            identifier,
            "this pattern is too short".to_string(),
            Span::new(
                SourceId(0),
                string_pattern
                    .string_lit_token()
                    .unwrap()
                    .text_range()
                    .start()
                    .into(),
                string_pattern
                    .string_lit_token()
                    .unwrap()
                    .text_range()
                    .end()
                    .into(),
            ),
            note,
        )));
    }

    Ok(PatternInRule {
        identifier,
        pattern: Pattern::Literal(LiteralPattern {
            flags,
            xor_range,
            base64_alphabet: base64_alphabet.map(String::from),
            base64wide_alphabet: base64wide_alphabet.map(String::from),
            anchored_at: None,

            text,
        }),
    })
}

fn hex_pattern_from_ast(
    warnings: &mut Vec<warnings::Warning>,
    report_builder: &ReportBuilder,
    pattern: yara_parser::VariableStmt,
) -> Result<PatternInRule, Box<CompileError>> {
    let identifier = pattern.variable_token().unwrap().text().to_string();
    let hex_pattern = pattern.pattern().unwrap();

    for modifier in hex_pattern.pattern_mods() {
        if modifier.base64_token().is_some()
            || modifier.base64wide_token().is_some()
            || modifier.xor_token().is_some()
            || modifier.nocase_token().is_some()
            || modifier.fullword_token().is_some()
            || modifier.ascii_token().is_some()
            || modifier.wide_token().is_some()
        {
            return Err(Box::new(CompileError::invalid_regexp_modifier(
                report_builder,
                "this modifier can't be applied to a hex pattern".to_string(),
                Span::new(
                    SourceId(0),
                    modifier.syntax().text_range().start().into(),
                    modifier.syntax().text_range().end().into(),
                ),
            )));
        }
        // private not supported on compiler level
    }

    Ok(PatternInRule {
        identifier: identifier.clone(),
        pattern: Pattern::Regexp(RegexpPattern {
            flags: PatternFlagSet::from(PatternFlags::Ascii),
            hir: re::hir::Hir::from(hex_pattern_hir_from_ast(
                warnings,
                report_builder,
                hex_pattern,
                identifier,
            )?),
            anchored_at: None,
        }),
    })
}

fn regex_pattern_from_ast(
    report_builder: &ReportBuilder,
    pattern: yara_parser::VariableStmt,
) -> Result<PatternInRule, Box<CompileError>> {
    let mut flags = PatternFlagSet::none();

    let identifier = pattern.variable_token().unwrap().text().to_string();
    let regex_pattern = pattern.pattern().unwrap();

    //Pattern modifiers
    let mut modifiers = BTreeMap::new();

    // Set default ascii flag for empty modifiers
    if regex_pattern.pattern_mods().next().is_none() {
        flags.set(PatternFlags::Ascii);
    }
    for modifier in regex_pattern.pattern_mods() {
        // Check if there are no duplicates in modifiers
        if modifiers
            .insert(
                modifier
                    .syntax()
                    .first_child_or_token()
                    .unwrap()
                    .into_token()
                    .unwrap()
                    .text()
                    .to_string(),
                modifier.clone(),
            )
            .is_some()
        {
            return Err(Box::new(CompileError::duplicate_modifier(
                report_builder,
                Span::new(
                    SourceId(0),
                    modifier.syntax().text_range().start().into(),
                    modifier.syntax().text_range().end().into(),
                ),
            )));
        }

        if modifier.ascii_token().is_some() || modifier.wide_token().is_none()
        {
            flags.set(PatternFlags::Ascii);
        }

        if modifier.wide_token().is_some() {
            flags.set(PatternFlags::Wide);
        }

        if modifier.fullword_token().is_some() {
            flags.set(PatternFlags::Fullword);
        }

        if modifier.nocase_token().is_some()
            || regex_pattern
                .regex_pattern()
                .unwrap()
                .regex_mods()
                .any(|m| m.case_insensitive_token().is_some())
        {
            flags.set(PatternFlags::Nocase);
        }

        if modifier.base64_token().is_some()
            || modifier.base64wide_token().is_some()
            || modifier.xor_token().is_some()
        {
            return Err(Box::new(CompileError::invalid_regexp_modifier(
                report_builder,
                "this modifier can't be applied to a regex pattern"
                    .to_string(),
                Span::new(
                    SourceId(0),
                    modifier.syntax().text_range().start().into(),
                    modifier.syntax().text_range().end().into(),
                ),
            )));
        }
    }

    validate_pattern_modifiers(&modifiers, report_builder)?;

    let hir = re::parser::Parser::new()
        .force_case_insensitive(flags.contains(PatternFlags::Nocase))
        .allow_mixed_greediness(false)
        .parse(pattern.pattern().unwrap().regex_pattern().unwrap())
        .map_err(|err| {
            re_error_to_compile_error(
                report_builder,
                pattern.pattern().unwrap().regex_pattern().unwrap(),
                err,
            )
        })?;

    Ok(PatternInRule {
        identifier,
        pattern: Pattern::Regexp(RegexpPattern {
            flags,
            hir,
            anchored_at: None,
        }),
    })
}

fn validate_pattern_modifiers(
    modifiers: &BTreeMap<String, yara_parser::PatternMod>,
    report_builder: &ReportBuilder,
) -> Result<(), Box<CompileError>> {
    let invalid_combinations = [
        ("xor", modifiers.get("xor"), "nocase", modifiers.get("nocase")),
        ("base64", modifiers.get("base64"), "nocase", modifiers.get("nocase")),
        (
            "base64wide",
            modifiers.get("base64wide"),
            "nocase",
            modifiers.get("nocase"),
        ),
        (
            "base64",
            modifiers.get("base64"),
            "fullword",
            modifiers.get("fullword"),
        ),
        (
            "base64wide",
            modifiers.get("base64wide"),
            "fullword",
            modifiers.get("fullword"),
        ),
        ("base64", modifiers.get("base64"), "xor", modifiers.get("xor")),
        (
            "base64wide",
            modifiers.get("base64wide"),
            "xor",
            modifiers.get("xor"),
        ),
    ];
    // Check for invalid modifier combinations

    for &(flag1, flag1_option, flag2, flag2_option) in &invalid_combinations {
        if flag1_option.is_some() && flag2_option.is_some() {
            return Err(Box::new(CompileError::invalid_modifier_combination(
                report_builder,
                flag1.to_string(),
                flag2.to_string(),
                Span::new(
                    SourceId(0),
                    flag1_option.unwrap().syntax().text_range().start().into(),
                    flag1_option.unwrap().syntax().text_range().end().into(),
                ),
                Span::new(
                    SourceId(0),
                    flag2_option.unwrap().syntax().text_range().start().into(),
                    flag2_option.unwrap().syntax().text_range().end().into(),
                ),
                Some("these two modifiers can't be used together".to_string()),
            )));
        }
    }
    Ok(())
}

fn validate_xor(
    modifier: yara_parser::PatternMod,
    report_builder: &ReportBuilder,
) -> Result<(u8, u8), Box<CompileError>> {
    let mut lower_bound = 0;
    let mut upper_bound = 255;
    if modifier.xor_range().is_some() {
        let lhs = modifier.xor_range().unwrap().lhs();
        let rhs = modifier.xor_range().unwrap().rhs();

        lower_bound = integer_lit_from_cst::<u8>(report_builder, lhs.clone())?;
        if modifier.xor_range().unwrap().hyphen_token().is_some() {
            upper_bound =
                integer_lit_from_cst::<u8>(report_builder, rhs.clone())?;
        } else {
            upper_bound = integer_lit_from_cst::<u8>(report_builder, lhs)?;
        }

        if lower_bound > upper_bound {
            return Err(Box::new(CompileError::invalid_range(
                report_builder,
                Span::new(
                    SourceId(0),
                    rhs.text_range().start().into(),
                    rhs.text_range().end().into(),
                ),
            )));
        }
    }
    Ok((lower_bound, upper_bound))
}

fn validate_base64_alphabet(
    base64alphabet: yara_parser::BaseAlphabet,
    report_builder: &ReportBuilder,
) -> Result<String, Box<CompileError>> {
    let alphabet_token = base64alphabet.string_lit_token().unwrap();
    let temp =
        string_lit_from_cst(report_builder, alphabet_token, false).unwrap();
    let alphabet_str = unsafe { temp.to_str_unchecked() };

    match base64::alphabet::Alphabet::new(alphabet_str) {
        Ok(_) => Ok(alphabet_str.to_owned()),
        Err(err) => Err(Box::new(CompileError::invalid_base_64_alphabet(
            report_builder,
            err.to_string().to_lowercase(),
            Span::new(
                SourceId(0),
                base64alphabet
                    .string_lit_token()
                    .unwrap()
                    .text_range()
                    .start()
                    .into(),
                base64alphabet
                    .string_lit_token()
                    .unwrap()
                    .text_range()
                    .end()
                    .into(),
            ),
        ))),
    }
}

/// Given the AST for some expression, creates its IR.
pub(in crate::compiler) fn boolean_expr_from_ast(
    ctx: &mut CompileContext,
    expr: yara_parser::Expression,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    match &expr {
        yara_parser::Expression::BooleanTerm(term) => {
            if let Some(variable) = term.variable_token() {
                let anchor = anchor_from_ast(
                    ctx,
                    term.variable_anchor(),
                    parse_context,
                )?;

                if variable.text() != "$" {
                    if parse_context
                        .declared_patterns
                        .get(&variable.text()[1..])
                        .is_none()
                    {
                        return Err(Box::new(CompileError::unknown_pattern(
                            ctx.report_builder,
                            variable.text().to_string(),
                            Span::new(
                                SourceId(0),
                                variable.text_range().start().into(),
                                variable.text_range().end().into(),
                            ),
                        )));
                    }
                    parse_context
                        .unused_patterns
                        .remove(&variable.text()[1..]);
                } else {
                    return Ok(Expr::PatternMatchVar {
                        symbol: ctx.symbol_table.lookup("$").unwrap(),
                        anchor,
                    });
                }

                let pattern = ctx.get_pattern_mut(variable.text());
                if let Some(offset) = anchor.at() {
                    pattern.anchor_at(offset as usize);
                } else {
                    pattern.make_non_anchorable();
                }
                return Ok(Expr::PatternMatch {
                    pattern: ctx.get_pattern_index(variable.text()),
                    anchor: anchor,
                });
            }

            if let Some(bool) = term.bool_lit_token() {
                return Ok(Expr::Const {
                    type_value: TypeValue::const_bool_from(
                        bool.text() == "true",
                    ),
                });
            }

            if let Some(_) = term.not_token() {
                return not_expr_from_ast(
                    ctx,
                    term.boolean_term().unwrap(),
                    parse_context,
                );
            }

            if let Some(_) = term.defined_token() {
                return defined_expr_from_ast(
                    ctx,
                    term.boolean_term().unwrap(),
                    parse_context,
                );
            }

            if let Some(_) = term.l_paren_token() {
                if let Some(_) = term.boolean_expr() {
                    return boolean_expr_from_ast(
                        ctx,
                        yara_parser::Expression::BooleanExpr(
                            term.boolean_expr().unwrap(),
                        ),
                        parse_context,
                    );
                } else {
                    return boolean_expr_from_ast(
                        ctx,
                        yara_parser::Expression::BooleanTerm(
                            term.boolean_term().unwrap(),
                        ),
                        parse_context,
                    );
                }
            }

            if let Some(expr) = term.of_expr() {
                return of_expr_from_ast(ctx, expr, parse_context);
            }

            if let Some(expr) = term.for_expr() {
                return for_expr_from_ast(ctx, expr, parse_context);
            }

            if let Some(expr) = term.expr() {
                return expr_from_ast(ctx, expr, parse_context);
            }
            if let Some(bool_expr) = &term.boolean_term_expr() {
                match bool_expr.op_kind().unwrap() {
                    yara_parser::BinaryOp::BoolTermExprOp(op) => match op {
                        yara_parser::BoolTermExprOp::Eq => {
                            return eq_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Ne => {
                            return ne_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Gt => {
                            return gt_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Ge => {
                            return ge_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Lt => {
                            return lt_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Le => {
                            return le_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Contains => {
                            return contains_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::IContains => {
                            return icontains_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::StartsWith => {
                            return startswith_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::IStartsWith => {
                            return istartswith_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::EndsWith => {
                            return endswith_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::IEndsWith => {
                            return iendswith_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::IEquals => {
                            return iequals_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                        yara_parser::BoolTermExprOp::Matches => {
                            return matches_expr_from_ast(
                                ctx,
                                bool_expr,
                                parse_context,
                            )
                        }
                    },
                    _ => unreachable!(),
                }
            } else {
                unreachable!("Unsupported boolean term")
            }
        }
        yara_parser::Expression::BooleanExpr(expr) => {
            if let Some(op_kind) = expr.op_kind() {
                match op_kind {
                    yara_parser::BinaryOp::LogicOp(op) => match op {
                        yara_parser::LogicOp::And => {
                            return and_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::LogicOp::Or => {
                            return or_expr_from_ast(ctx, expr, parse_context)
                        }
                    },
                    _ => unreachable!("BooleanExpr without LogicOp"),
                }
            } else {
                return bool_expr_from_ast(
                    ctx,
                    expr.lhs().unwrap(),
                    parse_context,
                );
            }
        }
    }
}

pub(in crate::compiler) fn expr_from_ast(
    ctx: &mut CompileContext,
    expr: yara_parser::Expr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    match &expr {
        yara_parser::Expr::PrimaryExpr(expr) => {
            if let Some(int) = expr.int_lit_token() {
                return Ok(Expr::Const {
                    type_value: TypeValue::const_integer_from(
                        integer_lit_from_cst::<i64>(ctx.report_builder, int)?,
                    ),
                });
            }
            if let Some(float) = expr.float_lit_token() {
                return Ok(Expr::Const {
                    type_value: TypeValue::const_float_from(
                        float_lit_from_cst(ctx.report_builder, float)?,
                    ),
                });
            }
            if let Some(string) = expr.string_lit_token() {
                return Ok(Expr::Const {
                    type_value: TypeValue::const_string_from(
                        string_lit_from_cst(ctx.report_builder, string, true)?,
                    ),
                });
            }
            if let Some(_) = expr.tilde_token() {
                return bitwise_not_expr_from_ast(
                    ctx,
                    expr.expr().unwrap(),
                    parse_context,
                );
            }
            if let Some(_) = expr.hyphen_token() {
                return minus_expr_from_ast(
                    ctx,
                    expr.expr().unwrap(),
                    parse_context,
                );
            }
            if let Some(_) = expr.filesize_token() {
                return Ok(Expr::Filesize);
            }
            if let Some(entrypoint) = expr.entrypoint_token() {
                return Err(Box::new(CompileError::entrypoint_unsupported(
                    ctx.report_builder,
                    Span::new(SourceId(0), entrypoint.text_range().start().into(), entrypoint.text_range().end().into()),
                    Some("use `pe.entry_point`, `elf.entry_point` or `macho.entry_point`".to_string()),
                )));
            }
            if let Some(regexp) = expr.regex_pattern() {
                let regex_lit = regexp.clone().syntax().text().to_string();
                re::parser::Parser::new().parse(regexp.clone()).map_err(
                    |err| {
                        re_error_to_compile_error(
                            ctx.report_builder,
                            regexp,
                            err,
                        )
                    },
                )?;

                return Ok(Expr::Const {
                    type_value: TypeValue::Regexp(Some(Regexp::new(
                        regex_lit,
                    ))),
                });
            }
            if let Some(_) = expr.l_paren_token() {
                return expr_from_ast(
                    ctx,
                    expr.expr().unwrap(),
                    parse_context,
                );
            }
            if let Some(expr) = expr.variable_count() {
                let var_token = expr.variable_count_token().unwrap();
                let ident = var_token.text();

                if ident != "#"
                    && parse_context
                        .declared_patterns
                        .get(&ident[1..])
                        .is_none()
                {
                    return Err(Box::new(CompileError::unknown_pattern(
                        ctx.report_builder,
                        ident.to_string(),
                        Span::new(
                            SourceId(0),
                            var_token.text_range().start().into(),
                            var_token.text_range().end().into(),
                        ),
                    )));
                }

                // Remove from ctx.unused_patterns, indicating that the
                // identifier has been used.
                parse_context.unused_patterns.remove(&ident[1..]);

                match (ident, expr.in_range()) {
                    ("#", Some(range)) => {
                        return Ok(Expr::PatternCountVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            range: Some(range_from_ast(
                                ctx,
                                range.range().unwrap(),
                                parse_context,
                            )?),
                        })
                    }
                    ("#", None) => {
                        return Ok(Expr::PatternCountVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            range: None,
                        })
                    }
                    // Cases where the identifier is not `#`.
                    (_, Some(range)) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternCount {
                            pattern: ctx.get_pattern_index(ident),
                            range: Some(range_from_ast(
                                ctx,
                                range.range().unwrap(),
                                parse_context,
                            )?),
                        });
                    }
                    (_, None) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternCount {
                            pattern: ctx.get_pattern_index(ident),
                            range: None,
                        });
                    }
                }
            }
            if let Some(expr) = expr.variable_length() {
                let var_token = expr.variable_length_token().unwrap();
                let ident = var_token.text();

                if ident.len() > 1
                    && parse_context
                        .declared_patterns
                        .get(&ident[1..])
                        .is_none()
                {
                    return Err(Box::new(CompileError::unknown_pattern(
                        ctx.report_builder,
                        ident.to_string(),
                        Span::new(
                            SourceId(0),
                            var_token.text_range().start().into(),
                            var_token.text_range().end().into(),
                        ),
                    )));
                }

                // Remove from ctx.unused_patterns, indicating that the
                // identifier has been used.
                parse_context.unused_patterns.remove(&ident[1..]);

                // If the identifier is just `!` we are inside a loop and we don't
                // know which is the PatternId because `!` refers to a different
                // pattern on each iteration. In those cases the symbol table must
                // contain an entry for `$`, corresponding to the variable that
                // holds the current PatternId for the loop.
                match (ident, expr.expr_index()) {
                    // Cases where the identifier is `!`.
                    ("!", Some(index)) => {
                        return Ok(Expr::PatternLengthVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            index: Some(Box::new(integer_in_range_from_ast(
                                ctx,
                                index.expr().unwrap(),
                                1..=i64::MAX,
                                parse_context,
                            )?)),
                        })
                    }
                    ("!", None) => {
                        return Ok(Expr::PatternLengthVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            index: None,
                        })
                    }
                    // Cases where the identifier is not `!`.
                    (_, Some(index)) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternLength {
                            pattern: ctx.get_pattern_index(ident),
                            index: Some(Box::new(integer_in_range_from_ast(
                                ctx,
                                index.expr().unwrap(),
                                1..=i64::MAX,
                                parse_context,
                            )?)),
                        });
                    }
                    (_, None) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternLength {
                            pattern: ctx.get_pattern_index(ident),
                            index: None,
                        });
                    }
                }
            }
            if let Some(expr) = expr.variable_offset() {
                let var_token = expr.variable_offset_token().unwrap();
                let ident = var_token.text();

                if ident.len() > 1
                    && parse_context
                        .declared_patterns
                        .get(&ident[1..])
                        .is_none()
                {
                    return Err(Box::new(CompileError::unknown_pattern(
                        ctx.report_builder,
                        ident.to_string(),
                        Span::new(
                            SourceId(0),
                            var_token.text_range().start().into(),
                            var_token.text_range().end().into(),
                        ),
                    )));
                }

                // Remove from ctx.unused_patterns, indicating that the
                // identifier has been used.
                parse_context.unused_patterns.remove(&ident[1..]);

                // If the identifier is just `!` we are inside a loop and we don't
                // know which is the PatternId because `!` refers to a different
                // pattern on each iteration. In those cases the symbol table must
                // contain an entry for `$`, corresponding to the variable that
                // holds the current PatternId for the loop.
                match (ident, expr.expr_index()) {
                    // Cases where the identifier is `!`.
                    ("@", Some(index)) => {
                        return Ok(Expr::PatternOffsetVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            index: Some(Box::new(integer_in_range_from_ast(
                                ctx,
                                index.expr().unwrap(),
                                1..=i64::MAX,
                                parse_context,
                            )?)),
                        })
                    }
                    ("@", None) => {
                        return Ok(Expr::PatternOffsetVar {
                            symbol: ctx.symbol_table.lookup("$").unwrap(),
                            index: None,
                        })
                    }
                    // Cases where the identifier is not `@`.
                    (_, Some(index)) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternOffset {
                            pattern: ctx.get_pattern_index(ident),
                            index: Some(Box::new(integer_in_range_from_ast(
                                ctx,
                                index.expr().unwrap(),
                                1..=i64::MAX,
                                parse_context,
                            )?)),
                        });
                    }
                    (_, None) => {
                        ctx.get_pattern_mut(ident).make_non_anchorable();
                        return Ok(Expr::PatternOffset {
                            pattern: ctx.get_pattern_index(ident),
                            index: None,
                        });
                    }
                }
            }
            if let Some(expr) = expr.identifier_node() {
                return identifier_node_from_ast(ctx, expr, parse_context);
            }
            if let Some(expr) = expr.field_acess() {
                let field_access: Vec<_> = expr.identifier_nodes().collect();
                if field_access.len() != 0 {
                    let mut operands = Vec::new();
                    for operand in field_access.iter().dropping_back(1) {
                        let expr = identifier_node_from_ast(
                            ctx,
                            operand.to_owned(),
                            parse_context,
                        )?;
                        check_type(
                            ctx,
                            expr.ty(),
                            Span::new(
                                SourceId(0),
                                operand.syntax().text_range().start().into(),
                                operand.syntax().text_range().end().into(),
                            ),
                            &[Type::Struct],
                        )?;
                        ctx.current_symbol_table =
                            Some(expr.type_value().symbol_table());

                        operands.push(expr);
                    }

                    let last_operand = identifier_node_from_ast(
                        ctx,
                        field_access.last().unwrap().to_owned(),
                        parse_context,
                    )?;

                    // If the last operand is constant, the whole expression is
                    // constant.
                    #[cfg(feature = "constant-folding")]
                    if let Expr::Const { type_value, .. } = last_operand {
                        // A constant always have a defined value.
                        assert!(type_value.is_const());
                        return Ok(Expr::Const { type_value });
                    }

                    operands.push(last_operand);

                    return Ok(Expr::FieldAccess { operands });
                }
            }
            unreachable!("Unsupported primary expression");
        }
        yara_parser::Expr::FunctionCallExpr(expr) => {
            return func_call_from_ast(ctx, expr, parse_context);
        }
        yara_parser::Expr::IndexingExpr(expr) => {
            return indexing_expr_from_ast(ctx, expr, parse_context);
        }
        yara_parser::Expr::ExprBody(expr) => {
            if let Some(op) = expr.op_kind() {
                match op {
                    yara_parser::BinaryOp::ExprOp(op) => match op {
                        yara_parser::ExprOp::Add => {
                            return add_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Sub => {
                            return sub_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Mul => {
                            return mul_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Div => {
                            return div_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Mod => {
                            return mod_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Shl => {
                            return shl_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::Shr => {
                            return shr_expr_from_ast(ctx, expr, parse_context)
                        }
                        yara_parser::ExprOp::BitAnd => {
                            return bitwise_and_expr_from_ast(
                                ctx,
                                expr,
                                parse_context,
                            )
                        }
                        yara_parser::ExprOp::BitOr => {
                            return bitwise_or_expr_from_ast(
                                ctx,
                                expr,
                                parse_context,
                            )
                        }
                        yara_parser::ExprOp::BitXor => {
                            return bitwise_xor_expr_from_ast(
                                ctx,
                                expr,
                                parse_context,
                            )
                        }
                        yara_parser::ExprOp::Dot => {
                            let mut operands = Vec::new();
                            let span = Span::new(
                                SourceId(0),
                                expr.lhs()
                                    .unwrap()
                                    .syntax()
                                    .text_range()
                                    .start()
                                    .into(),
                                expr.lhs()
                                    .unwrap()
                                    .syntax()
                                    .text_range()
                                    .end()
                                    .into(),
                            );

                            let expr_l = expr_from_ast(
                                ctx,
                                expr.lhs().unwrap(),
                                parse_context,
                            )?;

                            check_type(
                                ctx,
                                expr_l.ty(),
                                span,
                                &[Type::Struct],
                            )?;

                            ctx.current_symbol_table =
                                Some(expr_l.type_value().symbol_table());

                            operands.push(expr_l);

                            let last_operand = expr_from_ast(
                                ctx,
                                expr.rhs().unwrap(),
                                parse_context,
                            )?;

                            // If the last operand is constant, the whole expression is
                            // constant.
                            #[cfg(feature = "constant-folding")]
                            if let Expr::Const { type_value, .. } =
                                last_operand
                            {
                                // A constant always have a defined value.
                                assert!(type_value.is_const());
                                return Ok(Expr::Const { type_value });
                            }

                            operands.push(last_operand);

                            return Ok(Expr::FieldAccess { operands });
                        }
                    },
                    _ => unreachable!("Expression without ExprOp"),
                }
            }
            todo!()
        }
    }
}

pub(in crate::compiler) fn bool_expr_from_ast(
    ctx: &mut CompileContext,
    ast: yara_parser::Expression,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let expr = boolean_expr_from_ast(ctx, ast.clone(), parse_context)?;
    warn_if_not_bool(
        ctx,
        expr.ty(),
        Span::new(
            SourceId(0),
            ast.syntax().text_range().start().into(),
            ast.syntax().text_range().end().into(),
        ),
    );
    Ok(expr)
}

fn of_expr_from_ast(
    ctx: &mut CompileContext,
    of: yara_parser::OfExpr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let quantifier =
        quantifier_from_ast(ctx, of.quantifier().unwrap(), parse_context)?;

    // Create new stack frame with 5 slots:
    //   1 slot for the loop variable, a bool in this case.
    //   4 up to slots used for loop control variables (see: emit::emit_for)
    let stack_frame = ctx.vars.new_frame(5);

    let (items, num_items) = if let Some(expr) = of.boolean_expr_tuple() {
        let mut tuple = Vec::new();

        for e in expr.boolean_exprs() {
            let expr = bool_expr_from_ast(
                ctx,
                yara_parser::Expression::BooleanExpr(e.clone()),
                parse_context,
            )?;
            check_type(
                ctx,
                expr.ty(),
                Span::new(
                    SourceId(0),
                    e.syntax().text_range().start().into(),
                    e.syntax().text_range().end().into(),
                ),
                &[Type::Bool],
            )?;
            tuple.push(expr);
        }

        let num_items = tuple.len();
        (OfItems::BoolExprTuple(tuple), num_items)
    } else if let Some(pattern_tuple) = of.pattern_ident_tuple() {
        let pattern_indexes =
            pattern_set_from_ast(ctx, pattern_tuple, parse_context)?;
        let num_patterns = pattern_indexes.len();
        (OfItems::PatternSet(pattern_indexes), num_patterns)
    } else if let Some(them) = of.them_token() {
        let pattern_indexes: Vec<PatternIdx> =
            (0..ctx.current_rule_patterns.len()).map(|i| i.into()).collect();

        if pattern_indexes.is_empty() {
            return Err(Box::new(CompileError::empty_pattern_set(
                ctx.report_builder,
                Span::new(
                    SourceId(0),
                    them.text_range().start().into(),
                    them.text_range().end().into(),
                ),
                Some("this rule doesn't define any patterns".to_string()),
            )));
        }

        // Make all the patterns in the set non-anchorable.
        for pattern in ctx.current_rule_patterns.iter_mut() {
            pattern.make_non_anchorable();
        }
        let len = pattern_indexes.len();

        parse_context.unused_patterns.clear();
        (OfItems::PatternSet(pattern_indexes), len)
    } else {
        unreachable!();
    };

    //If the quantifier expression is greater than the number of items,
    //the `of` expression is always false.
    if let Quantifier::Expr(expr) = &quantifier {
        if let TypeValue::Integer(Value::Const(value)) = expr.type_value() {
            if value > num_items.try_into().unwrap() {
                ctx.warnings.push(Warning::invariant_boolean_expression(
                    ctx.report_builder,
                    false,
                    Span::new(
                        SourceId(0),
                        of.syntax().text_range().start().into(),
                        of.syntax().text_range().end().into(),
                    ),
                    Some(format!(
                        "the expression requires {} matching patterns out of {}",
                        value, num_items
                    )),
                ));
            }
        }
    }

    // The anchor `at <expr>` is being used with a quantifier that is not `any`
    // or `none`, but this usually doesn't make sense. For example consider the
    // expression...
    //
    //   all of ($a, $b) at 0
    //
    // This means that both $a and $b must match at offset 0, which won't happen
    // unless $a and $b are overlapping patterns. In the other hand, these
    // expressions make perfect sense...
    //
    //  none of ($a, $b) at 0
    //  any of ($a, $b) at 0
    //
    // Raise a warning in those cases that are probably wrong.
    //
    if let Some(_) = of.variable_anchor() {
        let raise_warning = match &quantifier {
            // `all of <items> at <expr>`: the warning is raised only if there
            // are more than one item. `all of ($a) at 0` doesn't raise a
            // warning.
            Quantifier::All { .. } => num_items > 1,
            // `<expr> of <items> at <expr>: the warning is raised if <expr> is
            // 2 or more.
            Quantifier::Expr(expr) => match expr.type_value() {
                TypeValue::Integer(Value::Const(value)) => value >= 2,
                _ => false,
            },
            // `<expr>% of <items> at <expr>: the warning is raised if the
            // <expr> percent of the items is 2 or more.
            Quantifier::Percentage(expr) => match expr.type_value() {
                TypeValue::Integer(Value::Const(percentage)) => {
                    num_items as f64 * percentage as f64 / 100.0 >= 2.0
                }
                _ => false,
            },
            Quantifier::None { .. } | Quantifier::Any { .. } => false,
        };

        if raise_warning {
            ctx.warnings.push(Warning::potentially_wrong_expression(
                ctx.report_builder,
                Span::new(
                    SourceId(0),
                    of.quantifier()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .start()
                        .into(),
                    of.variable_anchor()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .end()
                        .into(),
                ),
                Span::new(
                    SourceId(0),
                    of.variable_anchor()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .start()
                        .into(),
                    of.variable_anchor()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .end()
                        .into(),
                ),
            ));
        }
    }

    let anchor = anchor_from_ast(ctx, of.variable_anchor(), parse_context)?;

    ctx.vars.unwind(&stack_frame);

    Ok(Expr::Of(Box::new(Of { quantifier, items, anchor, stack_frame })))
}

fn identifier_node_from_ast(
    ctx: &mut CompileContext,
    ident_node: yara_parser::IdentifierNode,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let current_symbol_table = ctx.current_symbol_table.take();
    let ident = ident_node.identifier_token().unwrap();
    let ident_name = ident.text();

    let symbol = if let Some(symbol_table) = &current_symbol_table {
        symbol_table.lookup(ident_name)
    } else {
        ctx.symbol_table.lookup(ident_name)
    };

    if symbol.is_none() {
        // If the current symbol table is `None` it means that the
        // identifier is not a field or method of some structure.
        return if current_symbol_table.is_none() {
            Err(Box::new(CompileError::unknown_identifier(
                ctx.report_builder,
                ident_name.to_string(),
                Span::new(
                    SourceId(0),
                    ident.text_range().start().into(),
                    ident.text_range().end().into(),
                ),
                // Add a note about the missing import statement if
                // the unknown identifier is a module name.
                if BUILTIN_MODULES.contains_key(ident_name) {
                    Some(format!(
                                    "there is a module named `{}`, but the `import \"{}\"` statement is missing",
                                    ident_name,
                                    ident_name
                                ))
                } else {
                    None
                },
            )))
        } else {
            Err(Box::new(CompileError::unknown_field(
                ctx.report_builder,
                ident_name.to_string(),
                Span::new(
                    SourceId(0),
                    ident.text_range().start().into(),
                    ident.text_range().end().into(),
                ),
            )))
        };
    }

    let symbol = symbol.unwrap();

    // Return error if a global rule depends on a non-global rule. This
    // is an error because global rules are evaluated before non-global
    // rules, even if the global rule appears after the non-global one
    // in the source code. This means that by the time the global rule
    // is being evaluated we can't know if the non-global rule matched
    // or not.
    // A global rule can depend on another global rule. And non-global
    // rules can depend both on global rules and non-global ones.
    if let SymbolKind::Rule(rule_id) = symbol.kind() {
        let current_rule = ctx.get_current_rule();
        let used_rule = ctx.get_rule(*rule_id);
        if current_rule.is_global && !used_rule.is_global {
            return Err(Box::new(CompileError::wrong_rule_dependency(
                ctx.report_builder,
                ctx.ident_pool.get(current_rule.ident_id).unwrap().to_string(),
                ident_name.to_string(),
                current_rule.ident_span,
                used_rule.ident_span,
                Span::new(
                    SourceId(0),
                    ident.text_range().start().into(),
                    ident.text_range().end().into(),
                ),
            )));
        }
    }
    #[cfg(feature = "constant-folding")]
    {
        let type_value = symbol.type_value();
        if type_value.is_const() {
            return Ok(Expr::Const { type_value: type_value.clone() });
        }
    }

    return Ok(Expr::Ident { symbol });
}

fn for_expr_from_ast(
    ctx: &mut CompileContext,
    for_expr: yara_parser::ForExpr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let quantifier = quantifier_from_ast(
        ctx,
        for_expr.quantifier().unwrap(),
        parse_context,
    )?;
    if let Some(_) = for_expr.of_token() {
        let pattern_set = if let Some(them) = for_expr.them_token() {
            let pattern_indexes: Vec<PatternIdx> =
                (0..ctx.current_rule_patterns.len())
                    .map(|i| i.into())
                    .collect();

            if pattern_indexes.is_empty() {
                return Err(Box::new(CompileError::empty_pattern_set(
                    ctx.report_builder,
                    Span::new(
                        SourceId(0),
                        them.text_range().start().into(),
                        them.text_range().end().into(),
                    ),
                    Some("this rule doesn't define any patterns".to_string()),
                )));
            }

            // Make all the patterns in the set non-anchorable.
            for pattern in ctx.current_rule_patterns.iter_mut() {
                pattern.make_non_anchorable();
            }

            parse_context.unused_patterns.clear();
            pattern_indexes
        } else {
            pattern_set_from_ast(
                ctx,
                for_expr.pattern_ident_tuple().unwrap(),
                parse_context,
            )?
        };

        let mut stack_frame = ctx.vars.new_frame(5);
        let next_pattern_id = stack_frame.new_var(Type::Integer);
        let mut loop_vars = SymbolTable::new();

        loop_vars.insert(
            "$",
            Symbol::new(
                TypeValue::Integer(Value::Unknown),
                SymbolKind::Var(next_pattern_id),
            ),
        );

        ctx.symbol_table.push(Rc::new(loop_vars));

        let condition = bool_expr_from_ast(
            ctx,
            for_expr.expression().unwrap(),
            parse_context,
        )?;

        ctx.symbol_table.pop();
        ctx.vars.unwind(&stack_frame);

        return Ok(Expr::ForOf(Box::new(ForOf {
            quantifier,
            pattern_set,
            condition,
            stack_frame,
            variable: next_pattern_id,
        })));
    } else {
        let iterable = iterable_from_ast(
            ctx,
            for_expr.iterable().unwrap(),
            parse_context,
        )?;
        let expected_vars = match &iterable {
            Iterable::Range(_) => vec![TypeValue::Integer(Value::Unknown)],
            Iterable::ExprTuple(expressions) => {
                // All expressions in the tuple have the same type, we can use
                // the type of the first item in the tuple as the type of the
                // loop variable. Notice that we are using `clone_without_value`
                // instead of `clone`, because we want a TypeValue with the same
                // type than the first item in the tuple, but we don't want to
                // clone its actual value if known. The actual value for the
                // loop variable is not known until the loop is executed.
                vec![expressions
                    .first()
                    .unwrap()
                    .type_value()
                    .clone_without_value()]
            }
            Iterable::Expr(expr) => match expr.type_value() {
                TypeValue::Array(array) => vec![array.deputy()],
                TypeValue::Map(map) => match map.as_ref() {
                    Map::IntegerKeys { .. } => {
                        vec![TypeValue::Integer(Value::Unknown), map.deputy()]
                    }
                    Map::StringKeys { .. } => {
                        vec![TypeValue::String(Value::Unknown), map.deputy()]
                    }
                },
                _ => unreachable!(),
            },
        };
        let loop_vars: Vec<_> = for_expr.identifier_nodes().collect();

        // Make sure that the number of variables in the `for .. in` statement
        // corresponds to the number of values returned by the iterator. For
        // example, while most iterators return a single value, maps return two
        // of them: key and value.
        if loop_vars.len() != expected_vars.len() {
            let span = Span::new(
                SourceId(0),
                loop_vars
                    .first()
                    .unwrap()
                    .syntax()
                    .text_range()
                    .start()
                    .into(),
                loop_vars.first().unwrap().syntax().text_range().end().into(),
            );
            let span = span.combine(&Span::new(
                SourceId(0),
                loop_vars.last().unwrap().syntax().text_range().start().into(),
                loop_vars.last().unwrap().syntax().text_range().end().into(),
            ));
            return Err(Box::new(CompileError::assignment_mismatch(
                ctx.report_builder,
                loop_vars.len() as u8,
                expected_vars.len() as u8,
                Span::new(
                    SourceId(0),
                    for_expr
                        .iterable()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .start()
                        .into(),
                    for_expr
                        .iterable()
                        .unwrap()
                        .syntax()
                        .text_range()
                        .end()
                        .into(),
                ),
                span,
            )));
        }

        // Create stack frame with capacity for the loop variables, plus 4
        // temporary variables used for controlling the loop (see emit_for),
        // plus one additional variable used in loops over arrays and maps
        // (see emit_for_in_array and emit_for_in_map).
        let mut stack_frame = ctx.vars.new_frame(loop_vars.len() as i32 + 5);
        let mut symbols = SymbolTable::new();
        let mut variables = Vec::new();

        // TODO: raise warning when the loop identifier (e.g: "i") hides
        // an existing identifier with the same name.
        for (loop_var, type_value) in iter::zip(loop_vars, expected_vars) {
            let var = stack_frame.new_var(type_value.ty());
            variables.push(var);
            symbols.insert(
                loop_var.syntax().text(),
                Symbol::new(type_value, SymbolKind::Var(var)),
            );
        }

        // Put the loop variables into scope.
        ctx.symbol_table.push(Rc::new(symbols));

        let condition = bool_expr_from_ast(
            ctx,
            for_expr.expression().unwrap(),
            parse_context,
        )?;

        // Leaving the condition's scope. Remove loop variables.
        ctx.symbol_table.pop();

        ctx.vars.unwind(&stack_frame);

        Ok(Expr::ForIn(Box::new(ForIn {
            quantifier,
            variables,
            iterable,
            condition,
            stack_frame,
        })))
    }
}

fn iterable_from_ast(
    ctx: &mut CompileContext,
    iter: yara_parser::Iterable,
    parse_context: &mut Context,
) -> Result<Iterable, Box<CompileError>> {
    match iter {
        yara_parser::Iterable::Range(range) => {
            Ok(Iterable::Range(range_from_ast(ctx, range, parse_context)?))
        }
        yara_parser::Iterable::NestedExpr(expr) => {
            let span = Span::new(
                SourceId(0),
                expr.syntax().text_range().start().into(),
                expr.syntax().text_range().end().into(),
            );
            let expr =
                expr_from_ast(ctx, expr.expr().unwrap(), parse_context)?;
            // Make sure that the expression has a type that is iterable.
            check_type(ctx, expr.ty(), span, &[Type::Array, Type::Map])?;
            Ok(Iterable::Expr(expr))
        }
        yara_parser::Iterable::ExprTuple(expr_tuple) => {
            let mut e = Vec::new();
            let mut prev: Option<(Type, Span)> = None;
            for expr in expr_tuple.exprs() {
                let span = Span::new(
                    SourceId(0),
                    expr.syntax().text_range().start().into(),
                    expr.syntax().text_range().end().into(),
                );
                let expr = expr_from_ast(ctx, expr, parse_context)?;
                let ty = expr.ty();
                // Items in the tuple must be either integer, float, string
                // or bool.
                check_type(
                    ctx,
                    ty,
                    span,
                    &[Type::Integer, Type::Float, Type::String, Type::Bool],
                )?;
                // All items in the item must have the same type. Compare
                // with the previous item and return as soon as we find a
                // type mismatch.
                if let Some((prev_ty, prev_span)) = prev {
                    if prev_ty != ty {
                        return Err(Box::new(
                            CompileError::mismatching_types(
                                ctx.report_builder,
                                prev_ty.to_string(),
                                ty.to_string(),
                                prev_span,
                                span,
                            ),
                        ));
                    }
                }
                prev = Some((ty, span));
                e.push(expr);
            }
            Ok(Iterable::ExprTuple(e))
        }
    }
}

fn anchor_from_ast(
    ctx: &mut CompileContext,
    anchor: Option<yara_parser::VariableAnchor>,
    parse_context: &mut Context,
) -> Result<MatchAnchor, Box<CompileError>> {
    if let Some(anchor) = anchor {
        if let Some(_) = anchor.at_token() {
            return Ok(MatchAnchor::At(Box::new(
                non_negative_integer_from_ast(
                    ctx,
                    anchor.expr().unwrap(),
                    parse_context,
                )?,
            )));
        }
        if let Some(_) = anchor.in_token() {
            return Ok(MatchAnchor::In(range_from_ast(
                ctx,
                anchor.range().unwrap(),
                parse_context,
            )?));
        }
    }
    return Ok(MatchAnchor::None);
}

fn range_from_ast(
    ctx: &mut CompileContext,
    range: yara_parser::Range,
    parse_context: &mut Context,
) -> Result<Range, Box<CompileError>> {
    let lower_bound = Box::new(non_negative_integer_from_ast(
        ctx,
        range.lhs().unwrap(),
        parse_context,
    )?);

    let upper_bound = Box::new(non_negative_integer_from_ast(
        ctx,
        range.rhs().unwrap(),
        parse_context,
    )?);

    // If both the lower and upper bounds are known at compile time, make sure
    // that lower_bound <= upper_bound. If they are not know (because they are
    // variables, for example) we can't raise an error at compile time but it
    // will be handled at scan time.
    if let (
        TypeValue::Integer(Value::Const(lower_bound)),
        TypeValue::Integer(Value::Const(upper_bound)),
    ) = (lower_bound.type_value(), upper_bound.type_value())
    {
        if lower_bound > upper_bound {
            return Err(Box::new(CompileError::invalid_range(
                ctx.report_builder,
                Span::new(
                    SourceId(0),
                    range.syntax().text_range().start().into(),
                    range.syntax().text_range().end().into(),
                ),
            )));
        }
    }

    Ok(Range { lower_bound, upper_bound })
}

fn non_negative_integer_from_ast(
    ctx: &mut CompileContext,
    expr: yara_parser::Expr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let span = Span::new(
        SourceId(0),
        expr.syntax().text_range().start().into(),
        expr.syntax().text_range().end().into(),
    );
    let expr = expr_from_ast(ctx, expr, parse_context)?;
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    if let TypeValue::Integer(Value::Const(value)) = type_value {
        if value < 0 {
            return Err(Box::new(CompileError::unexpected_negative_number(
                ctx.report_builder,
                span,
            )));
        }
    }

    Ok(expr)
}

fn integer_in_range_from_ast(
    ctx: &mut CompileContext,
    expr: yara_parser::Expr,
    range: RangeInclusive<i64>,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let span = Span::new(
        SourceId(0),
        expr.syntax().text_range().start().into(),
        expr.syntax().text_range().end().into(),
    );

    let expr = expr_from_ast(ctx, expr, parse_context)?;
    let type_value = expr.type_value();

    check_type(ctx, type_value.ty(), span, &[Type::Integer])?;

    // If the value is known at compile time make sure that it is within
    // the given range.
    if let TypeValue::Integer(Value::Const(value)) = type_value {
        if !range.contains(&value) {
            return Err(Box::new(CompileError::number_out_of_range(
                ctx.report_builder,
                *range.start(),
                *range.end(),
                span,
            )));
        }
    }

    Ok(expr)
}

fn quantifier_from_ast(
    ctx: &mut CompileContext,
    quantifier: yara_parser::Quantifier,
    parse_context: &mut Context,
) -> Result<Quantifier, Box<CompileError>> {
    if let Some(_) = quantifier.all_token() {
        return Ok(Quantifier::All);
    }
    if let Some(_) = quantifier.any_token() {
        return Ok(Quantifier::Any);
    }
    if let Some(_) = quantifier.none_token() {
        return Ok(Quantifier::None);
    }
    if let Some(_) = quantifier.percentage_token() {
        return Ok(Quantifier::Percentage(integer_in_range_from_ast(
            ctx,
            yara_parser::Expr::PrimaryExpr(quantifier.primary_expr().unwrap()),
            0..=100,
            parse_context,
        )?));
    } else {
        return Ok(Quantifier::Expr(non_negative_integer_from_ast(
            ctx,
            yara_parser::Expr::PrimaryExpr(quantifier.primary_expr().unwrap()),
            parse_context,
        )?));
    }
}
//
fn pattern_set_from_ast(
    ctx: &mut CompileContext,
    pattern_set: yara_parser::PatternIdentTuple,
    parse_context: &mut Context,
) -> Result<Vec<PatternIdx>, Box<CompileError>> {
    let mut pattern_indexes = Vec::new();
    for item in pattern_set.variable_wildcards() {
        if item.star_token().is_some() {
            parse_context.unused_patterns.retain(|ident| {
                !ident.starts_with(&item.variable_token().unwrap().text()[1..])
            });
        } else {
            parse_context
                .unused_patterns
                .remove(&item.variable_token().unwrap().text()[1..]);
        }

        if !ctx
            .current_rule_patterns
            .iter()
            .any(|pattern| item.matches(pattern.identifier()))
        {
            return Err(Box::new(CompileError::empty_pattern_set(
                ctx.report_builder,
                Span::new(
                    SourceId(0),
                    item.syntax().text_range().start().into(),
                    item.syntax().text_range().end().into(),
                ),
                Some(format!(
                    "`{}` doesn't match any pattern identifier",
                    item.variable_token().unwrap().text(),
                )),
            )));
        }
    }

    for (i, pattern) in ctx.current_rule_patterns.iter_mut().enumerate() {
        // Iterate over the patterns in the set (e.g: $foo, $foo*) and
        // check if some of them matches the identifier.
        for p in pattern_set.variable_wildcards() {
            if p.matches(pattern.identifier()) {
                pattern_indexes.push(i.into());
                // All the patterns in the set are made non-anchorable.
                pattern.make_non_anchorable();
            }
        }
    }

    Ok(pattern_indexes)
}

fn indexing_expr_from_ast(
    ctx: &mut CompileContext,
    indexing_expr: &yara_parser::IndexingExpr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let primary = Box::new(expr_from_ast(
        ctx,
        yara_parser::Expr::PrimaryExpr(indexing_expr.primary_expr().unwrap()),
        parse_context,
    )?);

    match primary.type_value() {
        TypeValue::Array(array) => {
            let index = Box::new(non_negative_integer_from_ast(
                ctx,
                indexing_expr.expr_index().unwrap().expr().unwrap(),
                parse_context,
            )?);

            Ok(Expr::Lookup(Box::new(Lookup {
                type_value: array.deputy(),
                primary,
                index,
            })))
        }
        TypeValue::Map(map) => {
            let (key_ty, deputy_value) = match map.borrow() {
                Map::IntegerKeys { deputy: Some(value), .. } => {
                    (Type::Integer, value)
                }
                Map::StringKeys { deputy: Some(value), .. } => {
                    (Type::String, value)
                }
                _ => unreachable!(),
            };

            let index = Box::new(expr_from_ast(
                ctx,
                indexing_expr.expr_index().unwrap().expr().unwrap(),
                parse_context,
            )?);
            let ty = index.ty();

            // The type of the key/index expression should correspond
            // with the type of the map's keys.
            if key_ty != ty {
                return Err(Box::new(CompileError::wrong_type(
                    ctx.report_builder,
                    format!("`{}`", key_ty),
                    ty.to_string(),
                    Span::new(
                        SourceId(0),
                        indexing_expr
                            .expr_index()
                            .unwrap()
                            .syntax()
                            .text_range()
                            .start()
                            .into(),
                        indexing_expr
                            .expr_index()
                            .unwrap()
                            .syntax()
                            .text_range()
                            .end()
                            .into(),
                    ),
                )));
            }

            Ok(Expr::Lookup(Box::new(Lookup {
                type_value: deputy_value.clone(),
                primary,
                index,
            })))
        }
        type_value => Err(Box::new(CompileError::wrong_type(
            ctx.report_builder,
            format!("`{}` or `{}`", Type::Array, Type::Map),
            type_value.ty().to_string(),
            Span::new(
                SourceId(0),
                indexing_expr
                    .primary_expr()
                    .unwrap()
                    .syntax()
                    .text_range()
                    .start()
                    .into(),
                indexing_expr
                    .primary_expr()
                    .unwrap()
                    .syntax()
                    .text_range()
                    .end()
                    .into(),
            ),
        ))),
    }
}

fn func_call_from_ast(
    ctx: &mut CompileContext,
    func_call: &yara_parser::FunctionCallExpr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let callable = expr_from_ast(
        ctx,
        yara_parser::Expr::PrimaryExpr(func_call.primary_expr().unwrap()),
        parse_context,
    )?;

    let type_value = callable.type_value();

    check_type(
        ctx,
        type_value.ty(),
        Span::new(
            SourceId(0),
            func_call
                .primary_expr()
                .unwrap()
                .syntax()
                .text_range()
                .start()
                .into(),
            func_call
                .primary_expr()
                .unwrap()
                .syntax()
                .text_range()
                .end()
                .into(),
        ),
        &[Type::Func],
    )?;

    let args = func_call.expr_tuple().unwrap();

    let args_vec: Vec<_> = args.exprs().collect();

    let args_expr = args_vec
        .iter()
        .map(|arg| expr_from_ast(ctx, arg.to_owned(), parse_context))
        .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

    let arg_types: Vec<Type> = args_expr.iter().map(|arg| arg.ty()).collect();

    let mut expected_args = Vec::new();
    let mut matching_signature = None;
    let func = type_value.as_func();

    // Determine if any of the signatures for the called function matches
    // the provided arguments.
    for (i, signature) in func.signatures().iter().enumerate() {
        // If the function is actually a method, the first argument is always
        // the type the method belongs to (i.e: the self pointer). This
        // argument appears in the function's signature, but is not expected
        // to appear among the arguments in the call statement.
        let expected_arg_types: Vec<Type> = if func.method_of().is_some() {
            signature.args.iter().skip(1).map(|arg| arg.ty()).collect()
        } else {
            signature.args.iter().map(|arg| arg.ty()).collect()
        };

        if arg_types == expected_arg_types {
            matching_signature = Some((i, signature.result.clone()));
            break;
        }

        expected_args.push(expected_arg_types);
    }

    // No matching signature was found, that means that the arguments
    // provided were incorrect.
    if matching_signature.is_none() {
        return Err(Box::new(CompileError::wrong_arguments(
            ctx.report_builder,
            Span::new(
                SourceId(0),
                func_call
                    .expr_tuple()
                    .unwrap()
                    .syntax()
                    .text_range()
                    .start()
                    .into(),
                func_call
                    .expr_tuple()
                    .unwrap()
                    .syntax()
                    .text_range()
                    .end()
                    .into(),
            ),
            Some(format!(
                "accepted argument combinations:\n\n{}",
                expected_args
                    .iter()
                    .map(|v| {
                        format!(
                            "({})",
                            v.iter()
                                .map(|i| i.to_string())
                                .collect::<Vec<String>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<String>>()
                    .join("\n")
            )),
        )));
    }
    let (signature_index, type_value) = matching_signature.unwrap();

    return Ok(Expr::FuncCall(Box::new(FuncCall {
        callable,
        type_value,
        signature_index,
        args: args_expr,
    })));
}

fn matches_expr_from_ast(
    ctx: &mut CompileContext,
    expr: &yara_parser::BooleanTermExpr,
    parse_context: &mut Context,
) -> Result<Expr, Box<CompileError>> {
    let lhs_span = Span::new(
        SourceId(0),
        expr.lhs().unwrap().syntax().text_range().start().into(),
        expr.lhs().unwrap().syntax().text_range().end().into(),
    );

    let rhs_span = Span::new(
        SourceId(0),
        expr.rhs().unwrap().syntax().text_range().start().into(),
        expr.rhs().unwrap().syntax().text_range().end().into(),
    );

    let lhs =
        Box::new(expr_from_ast(ctx, expr.lhs().unwrap(), parse_context)?);
    let rhs =
        Box::new(expr_from_ast(ctx, expr.rhs().unwrap(), parse_context)?);

    check_type(ctx, lhs.ty(), lhs_span, &[Type::String])?;
    check_type(ctx, rhs.ty(), rhs_span, &[Type::Regexp])?;

    let expr = Expr::Matches { lhs, rhs };

    if cfg!(feature = "constant-folding") {
        Ok(expr.fold())
    } else {
        Ok(expr)
    }
}

fn check_type(
    ctx: &CompileContext,
    ty: Type,
    span: Span,
    accepted_types: &[Type],
) -> Result<(), Box<CompileError>> {
    if accepted_types.contains(&ty) {
        Ok(())
    } else {
        Err(Box::new(CompileError::wrong_type(
            ctx.report_builder,
            ErrorInfo::join_with_or(accepted_types, true),
            ty.to_string(),
            span,
        )))
    }
}

fn check_type2(
    ctx: &CompileContext,
    expr: yara_parser::Expression,
    ty: Type,
    accepted_types: &[Type],
) -> Result<(), Box<CompileError>> {
    if accepted_types.contains(&ty) {
        Ok(())
    } else {
        Err(Box::new(CompileError::wrong_type(
            ctx.report_builder,
            ErrorInfo::join_with_or(accepted_types, true),
            ty.to_string(),
            Span::new(
                SourceId(0),
                expr.syntax().text_range().start().into(),
                expr.syntax().text_range().end().into(),
            ),
        )))
    }
}

fn check_type2_term(
    ctx: &CompileContext,
    expr: yara_parser::Expr,
    ty: Type,
    accepted_types: &[Type],
) -> Result<(), Box<CompileError>> {
    if accepted_types.contains(&ty) {
        Ok(())
    } else {
        Err(Box::new(CompileError::wrong_type(
            ctx.report_builder,
            ErrorInfo::join_with_or(accepted_types, true),
            ty.to_string(),
            Span::new(
                SourceId(0),
                expr.syntax().text_range().start().into(),
                expr.syntax().text_range().end().into(),
            ),
        )))
    }
}

fn check_operands(
    ctx: &CompileContext,
    lhs_ty: Type,
    rhs_ty: Type,
    lhs_span: Span,
    rhs_span: Span,
    accepted_types: &[Type],
    compatible_types: &[Type],
) -> Result<(), Box<CompileError>> {
    // Both types must be known.
    assert!(!matches!(lhs_ty, Type::Unknown));
    assert!(!matches!(rhs_ty, Type::Unknown));

    check_type(ctx, lhs_ty, lhs_span, accepted_types)?;
    check_type(ctx, rhs_ty, rhs_span, accepted_types)?;

    let types_are_compatible = {
        // If the types are the same, they are compatible.
        (lhs_ty == rhs_ty)
            // If both types are in the list of compatible types,
            // they are compatible too.
            || (
            compatible_types.contains(&lhs_ty)
                && compatible_types.contains(&rhs_ty)
        )
    };

    if !types_are_compatible {
        return Err(Box::new(CompileError::mismatching_types(
            ctx.report_builder,
            lhs_ty.to_string(),
            rhs_ty.to_string(),
            lhs_span,
            rhs_span,
        )));
    }

    Ok(())
}

fn re_error_to_compile_error(
    report_builder: &ReportBuilder,
    regexp: yara_parser::RegexPattern,
    err: re::parser::Error,
) -> CompileError {
    match err {
        Error::SyntaxError { msg, span } => {
            CompileError::invalid_regexp(
                report_builder,
                msg,
                // the error span is relative to the start of the regexp, not to
                // the start of the source file, here we make it relative to the
                // source file.
                Span::new(
                    SourceId(0),
                    regexp
                        .regex_lit_token()
                        .unwrap()
                        .text_range()
                        .start()
                        .into(),
                    regexp
                        .regex_lit_token()
                        .unwrap()
                        .text_range()
                        .end()
                        .into(),
                )
                .subspan(span.start.offset, span.end.offset),
            )
        }
        Error::MixedGreediness {
            is_greedy_1,
            is_greedy_2,
            span_1,
            span_2,
        } => CompileError::mixed_greediness(
            report_builder,
            if is_greedy_1 { "greedy" } else { "non-greedy" }.to_string(),
            if is_greedy_2 { "greedy" } else { "non-greedy" }.to_string(),
            Span::new(
                SourceId(0),
                regexp.regex_lit_token().unwrap().text_range().start().into(),
                regexp.regex_lit_token().unwrap().text_range().end().into(),
            )
            .subspan(span_1.start.offset, span_1.end.offset),
            Span::new(
                SourceId(0),
                regexp.regex_lit_token().unwrap().text_range().start().into(),
                regexp.regex_lit_token().unwrap().text_range().end().into(),
            )
            .subspan(span_2.start.offset, span_2.end.offset),
        ),
    }
}

/// Produce a warning if the expression is not boolean.
pub(in crate::compiler) fn warn_if_not_bool(
    ctx: &mut CompileContext,
    ty: Type,
    span: Span,
) {
    let note = match ty {
        Type::Integer => Some(
            "non-zero integers are considered `true`, while zero is `false`"
                .to_string(),
        ),
        Type::Float => Some(
            "non-zero floats are considered `true`, while zero is `false`"
                .to_string(),
        ),
        Type::String => Some(
            r#"non-empty strings are considered `true`, while the empty string ("") is `false`"#
                .to_string(),
        ),
        _ => None,
    };

    if !matches!(ty, Type::Bool) {
        ctx.warnings.push(Warning::non_boolean_as_boolean(
            ctx.report_builder,
            ty.to_string(),
            span,
            note,
        ));
    }
}

macro_rules! gen_unary_op {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: yara_parser::BooleanTerm,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {
            let operand = Box::new(boolean_expr_from_ast(ctx, yara_parser::Expression::BooleanTerm(expr.clone()), parse_context)?);
            let operand_span = Span::new(SourceId(0), expr.syntax().text_range().start().into(), expr.syntax().text_range().end().into());

            // The `not` operator accepts integers, floats and strings because
            // those types can be casted to bool.
            check_type(
                ctx,
                operand.ty(),
                operand_span,
                &[$( $accepted_types ),+],
            )?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &operand, operand_span)?;
            }

            let expr = Expr::$variant { operand };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_unary_expr {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: yara_parser::Expr,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {
            let operand = Box::new(expr_from_ast(ctx, expr.clone(), parse_context)?);
            let operand_span = Span::new(SourceId(0), expr.syntax().text_range().start().into(), expr.syntax().text_range().end().into());

            check_type(
                ctx,
                operand.ty(),
                operand_span,
                &[$( $accepted_types ),+],
            )?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &operand, operand_span)?;
            }

            let expr = Expr::$variant { operand };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_binary_op {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &yara_parser::ExprBody,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {

            let lhs_span = Span::new(
                SourceId(0),
                expr.lhs().unwrap().syntax().text_range().start().into(),
                expr.lhs().unwrap().syntax().text_range().end().into(),
            );

            let rhs_span = Span::new(
                SourceId(0),
                expr.rhs().unwrap().syntax().text_range().start().into(),
                expr.rhs().unwrap().syntax().text_range().end().into(),
            );

            let lhs = Box::new(expr_from_ast(
                ctx,
                expr.lhs().unwrap(),
                parse_context,
            )?);
            let rhs = Box::new(expr_from_ast(
                ctx,
                expr.rhs().unwrap(),
                parse_context,
            )?);

            check_operands(
                ctx,
                lhs.ty(),
                rhs.ty(),
                lhs_span,
                rhs_span,
                &[$( $accepted_types ),+],
                &[$( $compatible_types ),+],
            )?;


            let check_fn:
                Option<fn(&mut CompileContext, &Expr, &Expr, Span, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &lhs, &rhs, lhs_span, rhs_span)?;
            }

            let expr = Expr::$variant { lhs, rhs };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_binary_expr {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &yara_parser::BooleanTermExpr,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {

            let lhs_span = Span::new(
                SourceId(0),
                expr.lhs().unwrap().syntax().text_range().start().into(),
                expr.lhs().unwrap().syntax().text_range().end().into(),
            );

            let rhs_span = Span::new(
                SourceId(0),
                expr.rhs().unwrap().syntax().text_range().start().into(),
                expr.rhs().unwrap().syntax().text_range().end().into(),
            );

            let lhs = Box::new(expr_from_ast(
                ctx,
                expr.lhs().unwrap(),
                parse_context,
            )?);
            let rhs = Box::new(expr_from_ast(
                ctx,
                expr.rhs().unwrap(),
                parse_context,
            )?);

            check_operands(
                ctx,
                lhs.ty(),
                rhs.ty(),
                lhs_span,
                rhs_span,
                &[$( $accepted_types ),+],
                &[$( $compatible_types ),+],
            )?;


            let check_fn:
                Option<fn(&mut CompileContext, &Expr, &Expr, Span, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            if let Some(check_fn) = check_fn {
                check_fn(ctx, &lhs, &rhs, lhs_span, rhs_span)?;
            }

            let expr = Expr::$variant { lhs, rhs };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_string_op {
    ($name:ident, $variant:ident) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &yara_parser::BooleanTermExpr,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {
            let lhs_span = Span::new(
                SourceId(0),
                expr.lhs().unwrap().syntax().text_range().start().into(),
                expr.lhs().unwrap().syntax().text_range().end().into(),
            );

            let rhs_span = Span::new(
                SourceId(0),
                expr.rhs().unwrap().syntax().text_range().start().into(),
                expr.rhs().unwrap().syntax().text_range().end().into(),
            );

            let lhs = Box::new(expr_from_ast(
                ctx,
                expr.lhs().unwrap(),
                parse_context,
            )?);
            let rhs = Box::new(expr_from_ast(
                ctx,
                expr.rhs().unwrap(),
                parse_context,
            )?);

            check_operands(
                ctx,
                lhs.ty(),
                rhs.ty(),
                lhs_span,
                rhs_span,
                &[Type::String],
                &[Type::String],
            )?;

            let expr = Expr::$variant { lhs, rhs };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_n_ary_operation {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &yara_parser::BooleanExpr,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {
            let accepted_types = &[$( $accepted_types ),+];
            let compatible_types = &[$( $compatible_types ),+];

            let operands = vec![expr.lhs().unwrap(), expr.rhs().unwrap()];
            let operands_hir: Vec<Expr> = operands
                .iter()
                .map(|expr| boolean_expr_from_ast(ctx, expr.clone(), parse_context))
                .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            // Make sure that all operands have one of the accepted types.
            for (hir, ast) in iter::zip(operands_hir.iter(), operands.clone()) {
                check_type2(ctx, ast.clone(), hir.ty(), accepted_types)?;
                if let Some(check_fn) = check_fn {
                    check_fn(
                        ctx,
                        hir,
                        Span::new(
                            SourceId(0),
                            ast.syntax().text_range().start().into(),
                            ast.syntax().text_range().end().into(),
                        ),
                    )?;
                }
            }

            // Iterate the operands in pairs (first, second), (second, third),
            // (third, fourth), etc.
            for ((lhs_hir, rhs_ast), (rhs_hir, lhs_ast)) in
                iter::zip(operands_hir.iter(), operands).tuple_windows()
            {
                let lhs_ty = lhs_hir.ty();
                let rhs_ty = rhs_hir.ty();

                let types_are_compatible = {
                    // If the types are the same, they are compatible.
                    (lhs_ty == rhs_ty)
                        // If both types are in the list of compatible types,
                        // they are compatible too.
                        || (
                        compatible_types.contains(&lhs_ty)
                            && compatible_types.contains(&rhs_ty)
                    )
                };

                if !types_are_compatible {
                    return Err(Box::new(CompileError::mismatching_types(
                            ctx.report_builder,
                            lhs_ty.to_string(),
                            rhs_ty.to_string(),
                            Span::new(
                                SourceId(0),
                                lhs_ast.syntax().text_range().start().into(),
                                lhs_ast.syntax().text_range().end().into(),
                            ),
                            Span::new(
                                SourceId(0),
                                rhs_ast.syntax().text_range().start().into(),
                                rhs_ast.syntax().text_range().end().into(),
                            ),
                        ),
                    ));
                }
            }

            let expr = Expr::$variant { operands: operands_hir };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

macro_rules! gen_n_ary_expr {
    ($name:ident, $variant:ident, $( $accepted_types:path )|+, $( $compatible_types:path )|+, $check_fn:expr) => {
        fn $name(
            ctx: &mut CompileContext,
            expr: &yara_parser::ExprBody,
            parse_context: &mut Context,
        ) -> Result<Expr, Box<CompileError>> {
            let accepted_types = &[$( $accepted_types ),+];
            let compatible_types = &[$( $compatible_types ),+];

            let operands = vec![expr.lhs().unwrap(), expr.rhs().unwrap()];
            let operands_hir: Vec<Expr> = operands
                .iter()
                .map(|expr| expr_from_ast(ctx, expr.clone(), parse_context))
                .collect::<Result<Vec<Expr>, Box<CompileError>>>()?;

            let check_fn:
                Option<fn(&mut CompileContext, &Expr, Span) -> Result<(), Box<CompileError>>>
                = $check_fn;

            // Make sure that all operands have one of the accepted types.
            for (hir, ast) in iter::zip(operands_hir.iter(), operands.clone()) {
                check_type2_term(ctx, ast.clone(), hir.ty(), accepted_types)?;
                if let Some(check_fn) = check_fn {
                    check_fn(
                        ctx,
                        hir,
                        Span::new(
                            SourceId(0),
                            ast.syntax().text_range().start().into(),
                            ast.syntax().text_range().end().into(),
                        ),
                    )?;
                }
            }

            // Iterate the operands in pairs (first, second), (second, third),
            // (third, fourth), etc.
            for ((lhs_hir, rhs_ast), (rhs_hir, lhs_ast)) in
                iter::zip(operands_hir.iter(), operands).tuple_windows()
            {
                let lhs_ty = lhs_hir.ty();
                let rhs_ty = rhs_hir.ty();

                let types_are_compatible = {
                    // If the types are the same, they are compatible.
                    (lhs_ty == rhs_ty)
                        // If both types are in the list of compatible types,
                        // they are compatible too.
                        || (
                        compatible_types.contains(&lhs_ty)
                            && compatible_types.contains(&rhs_ty)
                    )
                };

                if !types_are_compatible {
                    return Err(Box::new(CompileError::mismatching_types(
                            ctx.report_builder,
                            lhs_ty.to_string(),
                            rhs_ty.to_string(),
                            Span::new(
                                SourceId(0),
                                lhs_ast.syntax().text_range().start().into(),
                                lhs_ast.syntax().text_range().end().into(),
                            ),
                            Span::new(
                                SourceId(0),
                                rhs_ast.syntax().text_range().start().into(),
                                rhs_ast.syntax().text_range().end().into(),
                            ),
                        ),
                    ));
                }
            }

            let expr = Expr::$variant { operands: operands_hir };

            if cfg!(feature = "constant-folding") {
                Ok(expr.fold())
            } else {
                Ok(expr)
            }
        }
    };
}

//
gen_unary_op!(
    defined_expr_from_ast,
    Defined,
    Type::Bool | Type::Integer | Type::Float | Type::String,
    None
);

gen_unary_op!(
    not_expr_from_ast,
    Not,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // Raise warning if the operand is not bool.
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_n_ary_operation!(
    and_expr_from_ast,
    And,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_n_ary_operation!(
    or_expr_from_ast,
    Or,
    // Boolean operations accept integer, float and string operands.
    // If operands are not boolean they are casted to boolean.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    // All operand types can be mixed in a boolean operation, as they
    // are casted to boolean anyways.
    Type::Bool | Type::Integer | Type::Float | Type::String,
    Some(|ctx, operand, span| {
        warn_if_not_bool(ctx, operand.ty(), span);
        Ok(())
    })
);

gen_unary_expr!(minus_expr_from_ast, Minus, Type::Integer | Type::Float, None);

gen_n_ary_expr!(
    add_expr_from_ast,
    Add,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_expr!(
    sub_expr_from_ast,
    Sub,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_expr!(
    mul_expr_from_ast,
    Mul,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_expr!(
    div_expr_from_ast,
    Div,
    Type::Integer | Type::Float,
    Type::Integer | Type::Float,
    None
);

gen_n_ary_expr!(mod_expr_from_ast, Mod, Type::Integer, Type::Integer, None);

gen_binary_op!(
    shl_expr_from_ast,
    Shl,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Value::Const(value)) = rhs.type_value() {
            if value < 0 {
                return Err(Box::new(
                    CompileError::unexpected_negative_number(
                        ctx.report_builder,
                        rhs_span,
                    ),
                ));
            }
        }
        Ok(())
    })
);

gen_binary_op!(
    shr_expr_from_ast,
    Shr,
    Type::Integer,
    Type::Integer,
    Some(|ctx, _lhs, rhs, _lhs_span, rhs_span| {
        if let TypeValue::Integer(Value::Const(value)) = rhs.type_value() {
            if value < 0 {
                return Err(Box::new(
                    CompileError::unexpected_negative_number(
                        ctx.report_builder,
                        rhs_span,
                    ),
                ));
            }
        }
        Ok(())
    })
);

gen_unary_expr!(bitwise_not_expr_from_ast, BitwiseNot, Type::Integer, None);

gen_binary_op!(
    bitwise_and_expr_from_ast,
    BitwiseAnd,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_or_expr_from_ast,
    BitwiseOr,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_op!(
    bitwise_xor_expr_from_ast,
    BitwiseXor,
    Type::Integer,
    Type::Integer,
    None
);

gen_binary_expr!(
    eq_expr_from_ast,
    Eq,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_expr!(
    ne_expr_from_ast,
    Ne,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_expr!(
    gt_expr_from_ast,
    Gt,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_expr!(
    ge_expr_from_ast,
    Ge,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_expr!(
    lt_expr_from_ast,
    Lt,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_binary_expr!(
    le_expr_from_ast,
    Le,
    // Integers, floats and strings can be compared.
    Type::Integer | Type::Float | Type::String,
    // Integers can be compared with floats, but strings can be
    // compared only with another string.
    Type::Integer | Type::Float,
    None
);

gen_string_op!(contains_expr_from_ast, Contains);
gen_string_op!(icontains_expr_from_ast, IContains);
gen_string_op!(startswith_expr_from_ast, StartsWith);
gen_string_op!(istartswith_expr_from_ast, IStartsWith);
gen_string_op!(endswith_expr_from_ast, EndsWith);
gen_string_op!(iendswith_expr_from_ast, IEndsWith);
gen_string_op!(iequals_expr_from_ast, IEquals);
