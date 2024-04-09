/*! Functions for converting a hex pattern AST into a HIR. */

use crate::compiler::ir::ast2ir::integer_lit_from_cst;
use crate::compiler::CompileContext;
use crate::report::{ReportBuilder, SourceId};
use crate::span::Span;
use crate::warnings::Warning;
use nom::AsChar;
use num_traits::ToPrimitive;
use regex_syntax::hir;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use yara_parser::AstNode;

use crate::{compiler::ByteMaskCombinator, CompileError};

#[derive(Debug)]
struct HexJumpRange {
    start: Option<u8>,
    end: Option<u8>,
}

impl HexJumpRange {
    fn new(start: Option<u8>, end: Option<u8>) -> Self {
        HexJumpRange { start, end }
    }

    fn coalesce(&mut self, other: HexJumpRange) {
        match (self.start, other.start) {
            (Some(s1), Some(s2)) => self.start = Some(s1 + s2),
            (Some(s1), None) => self.start = Some(s1),
            (None, Some(s2)) => self.start = Some(s2),
            (None, None) => self.start = None,
        }
        match (self.end, other.end) {
            (Some(e1), Some(e2)) => self.end = Some(e1 + e2),
            (_, _) => self.end = None,
        }
    }
}

impl Display for HexJumpRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match (self.start, self.end) {
            (Some(start), Some(end)) => write!(f, "[{}-{}]", start, end),
            (Some(start), None) => write!(f, "[{}-]", start),
            (None, Some(end)) => write!(f, "[-{}]", end),
            (None, None) => write!(f, "[-]"),
        }
    }
}

pub(in crate::compiler) fn hex_pattern_hir_from_ast(
    warnings: &mut Vec<Warning>,
    report_builder: &ReportBuilder,
    pattern: yara_parser::Pattern,
    identifier: String,
) -> Result<hir::Hir, Box<CompileError>> {
    hex_tokens_hir_from_ast(
        warnings,
        report_builder,
        pattern.hex_pattern().unwrap().hex_token().unwrap(),
        identifier,
    )
}

fn process_hex_byte(
    report_builder: &ReportBuilder,
    hex_byte: yara_parser::HexByte,
    identifier: String,
) -> Result<hir::Hir, Box<CompileError>> {
    let byte_literal_string = hex_byte.syntax().text().to_string();
    let mut byte_literal = byte_literal_string.as_str();

    let mut value: u8 = 0x00;
    let mut mask: u8 = 0xFF;
    let mut negated = false;

    // If the byte starts with `~` is a negated byte.
    if let Some(b) = byte_literal.strip_prefix('~') {
        negated = true;
        byte_literal = b;
    }

    let mut nibbles = byte_literal.chars();
    let high_nibble = nibbles.next().unwrap();

    // High nibble is `?`, then it should be masked out.
    if high_nibble == '?' {
        mask &= 0x0F;
    } else {
        value |= (high_nibble.to_digit(16).unwrap() << 4) as u8;
    }

    if let Some(low_nibble) = nibbles.next() {
        // Low nibble is `?`, then it should be masked out.
        if low_nibble == '?' {
            mask &= 0xF0;
        } else {
            value |= low_nibble.to_digit(16).unwrap() as u8;
        }
    } else {
        return Err(Box::new(CompileError::invalid_pattern(
            report_builder,
            identifier,
            "uneven number of nibbles".to_string(),
            Span::new(
                SourceId(0),
                hex_byte.syntax().text_range().start().into(),
                hex_byte.syntax().text_range().end().into(),
            ),
            None,
        )));
    }

    // ~?? is not allowed.
    if negated && mask == 0x00 {
        return Err(Box::new(CompileError::invalid_pattern(
            report_builder,
            identifier,
            "negation of `??` is not allowed".to_string(),
            Span::new(
                SourceId(0),
                hex_byte.syntax().text_range().start().into(),
                hex_byte.syntax().text_range().end().into(),
            ),
            None,
        )));
    }

    if !negated {
        return Ok(hex_byte_hir_from_ast(value, mask));
    } else {
        let class = match hex_byte_hir_from_ast(value, mask).into_kind() {
            hir::HirKind::Class(mut class) => {
                class.negate();
                class
            }
            hir::HirKind::Literal(literal) => {
                let mut class = hir::ClassBytes::empty();
                for b in literal.0.iter() {
                    class.push(hir::ClassBytesRange::new(*b, *b));
                }
                class.negate();
                hir::Class::Bytes(class)
            }
            _ => unreachable!(),
        };
        return Ok(hir::Hir::class(class));
    }
}

fn process_hex_jumps(
    warnings: &mut Vec<Warning>,
    report_builder: &ReportBuilder,
    hex_jumps: Vec<yara_parser::HexJump>,
    identifier: String,
) -> Result<hir::Hir, Box<CompileError>> {
    let mut consecutive_jumps = false;

    // Get first jump
    let first_jump = match hex_jumps.first() {
        Some(jump) => jump,
        None => unreachable!("There should be at least one jump"),
    };

    let mut jump_span = Span::new(
        SourceId(0),
        first_jump.syntax().text_range().start().into(),
        first_jump.syntax().text_range().end().into(),
    );

    // lhs is mandatory
    let start =
        Some(integer_lit_from_cst::<u8>(report_builder, first_jump.lhs())?);

    // rhs is present only if there is a hyphen
    let end = if let Some(_) = first_jump.hyphen_token() {
        Some(integer_lit_from_cst::<u8>(report_builder, first_jump.rhs())?)
    } else {
        start
    };

    let mut current_range = HexJumpRange::new(start, end);

    // Loop over the rest of the hex jumps
    for next_jump in hex_jumps.iter().skip(1) {
        consecutive_jumps = true;
        let span = Span::new(
            SourceId(0),
            next_jump.syntax().text_range().start().into(),
            next_jump.syntax().text_range().end().into(),
        );

        // lhs is mandatory
        let start =
            Some(integer_lit_from_cst::<u8>(report_builder, next_jump.lhs())?);

        // rhs is present only if there is a hyphen
        let end = if let Some(_) = next_jump.hyphen_token() {
            Some(integer_lit_from_cst::<u8>(report_builder, next_jump.rhs())?)
        } else {
            start
        };

        let next_range = HexJumpRange::new(start, end);

        current_range.coalesce(next_range);
        jump_span = jump_span.combine(&span);
    }

    if consecutive_jumps {
        warnings.push(Warning::consecutive_jumps(
            report_builder,
            identifier.clone(),
            format!("{}", current_range),
            jump_span,
        ));
    }

    match (current_range.start, current_range.end) {
        (Some(0), Some(0)) => {
            return Err(Box::new(CompileError::invalid_pattern(
                report_builder,
                identifier.clone(),
                "zero-length jumps are useless, remove it".to_string(),
                jump_span,
                None,
            )));
        }
        (Some(start), Some(end)) if start > end => {
            return Err(Box::new(CompileError::invalid_pattern(
                report_builder,
                identifier.clone(),
                format!(
                    "lower bound ({}) is greater than upper bound ({})",
                    start, end
                ),
                jump_span,
                if consecutive_jumps {
                    Some(
                        "consecutive jumps were coalesced into a single one"
                            .to_string(),
                    )
                } else {
                    None
                },
            )));
        }
        _ => {}
    }

    Ok(hir::Hir::repetition(hir::Repetition {
        min: current_range.start.map(|start| start as u32).unwrap_or(0),
        max: current_range.end.map(|end| end as u32),
        greedy: false,
        sub: Box::new(hir::Hir::dot(hir::Dot::AnyByte)),
    }))
}

fn process_hex_alternative(
    warnings: &mut Vec<Warning>,
    report_builder: &ReportBuilder,
    hex_alternative: yara_parser::HexAlternative,
    identifier: String,
) -> Result<hir::Hir, Box<CompileError>> {
    let mut alternatives = Vec::new();

    alternatives.push(hex_tokens_hir_from_ast(
        warnings,
        report_builder,
        hex_alternative.hex_token().unwrap(),
        identifier.clone(),
    )?);

    for alt in hex_alternative.hex_pipes() {
        alternatives.push(hex_tokens_hir_from_ast(
            warnings,
            report_builder,
            alt.hex_token().unwrap(),
            identifier.clone(),
        )?)
    }

    Ok(hir::Hir::alternation(alternatives))
}

fn hex_tokens_hir_from_ast(
    warnings: &mut Vec<Warning>,
    report_builder: &ReportBuilder,
    tokens: yara_parser::HexToken,
    identifier: String,
) -> Result<hir::Hir, Box<CompileError>> {
    let mut hir_tokens = Vec::new();

    if tokens.hex_byte().is_some() {
        hir_tokens.push(process_hex_byte(
            report_builder,
            tokens.hex_byte().unwrap(),
            identifier.clone(),
        )?);
    } else if tokens.hex_alternative().is_some() {
        hir_tokens.push(process_hex_alternative(
            warnings,
            report_builder,
            tokens.hex_alternative().unwrap(),
            identifier.clone(),
        )?);
    }

    for token in tokens.hex_token_tails() {
        let hex_jumps_vec = token.hex_jumps().collect::<Vec<_>>();
        if hex_jumps_vec.len() > 0 {
            hir_tokens.push(process_hex_jumps(
                warnings,
                report_builder,
                hex_jumps_vec,
                identifier.clone(),
            )?);
        }

        if token.hex_byte().is_some() {
            hir_tokens.push(process_hex_byte(
                report_builder,
                token.hex_byte().unwrap(),
                identifier.clone(),
            )?);
        } else if token.hex_alternative().is_some() {
            hir_tokens.push(process_hex_alternative(
                warnings,
                report_builder,
                token.hex_alternative().unwrap(),
                identifier.clone(),
            )?);
        }
    }

    Ok(hir::Hir::concat(hir_tokens))
}

fn hex_byte_hir_from_ast(value: u8, mask: u8) -> hir::Hir {
    match mask {
        0xff => hir::Hir::literal([value]),
        0x00 => hir::Hir::dot(hir::Dot::AnyByte),
        _ => {
            hir::Hir::class(hir::Class::Bytes(hex_byte_to_class(value, mask)))
        }
    }
}

fn hex_byte_to_class(value: u8, mask: u8) -> hir::ClassBytes {
    // A zero bit in the mask indicates that the corresponding bit in the value
    // must will be ignored, but those ignored bits should be set to 0.
    assert_eq!(value & !mask, 0);

    let mut class = hir::ClassBytes::empty();
    for b in ByteMaskCombinator::new(value, mask) {
        class.push(hir::ClassBytesRange::new(b, b));
    }

    class
}

#[cfg(test)]
mod tests {
    use super::hex_byte_to_class;
    use crate::re::hir::class_to_masked_byte;
    use pretty_assertions::assert_eq;
    use regex_syntax::hir::{
        Class, ClassBytes, ClassBytesRange, Dot, Hir, HirKind, Repetition,
    };
    use yara_x_parser::ast::{
        HexAlternative, HexByte, HexJump, HexToken, HexTokens,
    };

    #[test]
    fn hex_byte_to_hir() {
        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x00, mask: 0x00 });
        assert_eq!(hir.to_string(), r"(?-u:[\x00-\xFF])");

        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x10, mask: 0xf0 });
        assert_eq!(hir.to_string(), r"(?-u:[\x10-\x1F])");

        let hir =
            super::hex_byte_hir_from_ast(&HexByte { value: 0x02, mask: 0x0f });
        assert_eq!(
            hir.to_string(),
            r#"(?-u:[\x02\x12"2BRbr\x82\x92\xA2\xB2\xC2\xD2\xE2\xF2])"#
        );
    }

    #[test]
    fn hex_tokens_to_hir() {
        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: b'a', mask: 0xff }),
                HexToken::Byte(HexByte { value: b'b', mask: 0xff }),
                HexToken::Byte(HexByte { value: b'c', mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::literal("abc".as_bytes())
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::literal([0x01, 0x02, 0x03])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x00, mask: 0x00 }),
                HexToken::Byte(HexByte { value: 0x05, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x06, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::dot(Dot::AnyByte),
                Hir::literal([0x05, 0x06]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::NotByte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 1),
                    ClassBytesRange::new(3, 255)
                ]))),
                Hir::literal([0x03]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::NotByte(HexByte { value: 0x40, mask: 0xfe }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01]),
                Hir::class(Class::Bytes(ClassBytes::new(vec![
                    ClassBytesRange::new(0, 0x3f),
                    ClassBytesRange::new(0x42, 0xff),
                ]))),
                Hir::literal([0x03]),
            ])
        );

        let tokens = HexTokens {
            tokens: vec![HexToken::Alternative(Box::new(HexAlternative {
                alternatives: vec![
                    HexTokens {
                        tokens: vec![HexToken::Byte(HexByte {
                            value: 0x01,
                            mask: 0xff,
                        })],
                    },
                    HexTokens {
                        tokens: vec![HexToken::Byte(HexByte {
                            value: 0x02,
                            mask: 0xff,
                        })],
                    },
                ],
            }))],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::alternation(
                vec![Hir::literal([0x01]), Hir::literal([0x02]),]
            )
        );

        let tokens = HexTokens {
            tokens: vec![
                HexToken::Byte(HexByte { value: 0x01, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x02, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x03, mask: 0xff }),
                HexToken::Jump(HexJump { start: None, end: None }),
                HexToken::Byte(HexByte { value: 0x05, mask: 0xff }),
                HexToken::Byte(HexByte { value: 0x06, mask: 0xff }),
            ],
        };

        assert_eq!(
            super::hex_tokens_hir_from_ast(&tokens),
            Hir::concat(vec![
                Hir::literal([0x01, 0x02, 0x03]),
                Hir::repetition(Repetition {
                    min: 0,
                    max: None,
                    greedy: false,
                    sub: Box::new(Hir::dot(Dot::AnyByte)),
                }),
                Hir::literal([0x05, 0x06]),
            ])
        );
    }

    #[test]
    fn class_to_hex() {
        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x30,
                mask: 0xF0
            })),
            Some(HexByte { value: 0x30, mask: 0xF0 })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x05,
                mask: 0x0F
            })),
            Some(HexByte { value: 0x05, mask: 0x0F })
        );

        assert_eq!(
            class_to_masked_byte(&hex_byte_to_class(&HexByte {
                value: 0x08,
                mask: 0xAA
            })),
            Some(HexByte { value: 0x08, mask: 0xAA })
        );

        assert_eq!(
            class_to_masked_byte(&ClassBytes::new(vec![
                ClassBytesRange::new(3, 4),
                ClassBytesRange::new(8, 8),
            ])),
            None,
        );

        assert_eq!(
            class_to_masked_byte(&ClassBytes::new(vec![
                ClassBytesRange::new(0, 0),
                ClassBytesRange::new(2, 2),
                ClassBytesRange::new(4, 4),
            ])),
            None,
        );

        if let HirKind::Class(Class::Bytes(class)) =
            Hir::dot(Dot::AnyByte).kind()
        {
            assert_eq!(
                class_to_masked_byte(class),
                Some(HexByte { value: 0x00, mask: 0x00 })
            );
        } else {
            unreachable!()
        }
    }
}
