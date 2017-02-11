// Copyright 2017 Rich Lane <lanerl@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! This module parses eBPF assembly language source code.

use combine::char::{alpha_num, char, digit, hex_digit, spaces, string};
use combine::{between, eof, many, many1, one_of, optional, Parser, ParseError, ParseResult, parser,
              sep_by, try, State, Stream};
use combine::primitives::{Error, Info};

/// Operand of an instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operand {
    /// Register number.
    Register(i64),
    /// Jump offset or immediate.
    Integer(i64),
    /// Register number and offset.
    Memory(i64, i64),
    /// Used for pattern matching.
    Nil,
}

/// Parsed instruction.
#[derive(Debug, PartialEq)]
pub struct Instruction {
    /// Instruction name.
    pub name: String,
    /// Operands.
    pub operands: Vec<Operand>,
}

fn ident<I>(input: I) -> ParseResult<String, I>
    where I: Stream<Item = char>
{
    many1(alpha_num()).parse_stream(input)
}

fn integer<I>(input: I) -> ParseResult<i64, I>
    where I: Stream<Item = char>
{
    let sign = optional(one_of("-+".chars())).map(|x| match x {
        Some('-') => -1,
        _ => 1,
    });
    let hex = string("0x")
        .with(many1(hex_digit()))
        .map(|x: String| u64::from_str_radix(&x, 16).unwrap() as i64);
    let dec = many1(digit()).map(|x: String| i64::from_str_radix(&x, 10).unwrap());
    (sign, try(hex).or(dec)).map(|(s, x)| s * x).parse_stream(input)
}

fn register<I>(input: I) -> ParseResult<i64, I>
    where I: Stream<Item = char>
{
    char('r')
        .with(many1(digit()))
        .map(|x: String| i64::from_str_radix(&x, 10).unwrap())
        .parse_stream(input)
}

fn operand<I>(input: I) -> ParseResult<Operand, I>
    where I: Stream<Item = char>
{
    let register_operand = parser(register).map(Operand::Register);
    let immediate = parser(integer).map(Operand::Integer);
    let memory = between(char('['),
                         char(']'),
                         (parser(register), optional(parser(integer))))
        .map(|t| Operand::Memory(t.0, t.1.unwrap_or(0)));
    register_operand.or(immediate).or(memory).parse_stream(input)
}

fn instruction<I>(input: I) -> ParseResult<Instruction, I>
    where I: Stream<Item = char>
{
    let operands = sep_by(parser(operand), char(',').skip(spaces()));
    (parser(ident).skip(spaces()), operands, spaces())
        .map(|t| {
            Instruction {
                name: t.0,
                operands: t.1,
            }
        })
        .parse_stream(input)
}

fn format_info(info: &Info<char, &str>) -> String {
    match *info {
        Info::Token(x) => format!("{:?}", x),
        Info::Range(x) => format!("{:?}", x),
        Info::Owned(ref x) => x.clone(),
        Info::Borrowed(x) => x.to_string(),
    }
}

fn format_error(error: &Error<char, &str>) -> String {
    match *error {
        Error::Unexpected(ref x) => format!("unexpected {}", format_info(x)),
        Error::Expected(ref x) => format!("expected {}", format_info(x)),
        Error::Message(ref x) => format_info(x),
        Error::Other(ref x) => format!("{:?}", x),
    }
}

fn format_parse_error(parse_error: ParseError<State<&str>>) -> String {
    format!("Parse error at line {} column {}: {}",
            parse_error.position.line,
            parse_error.position.column,
            parse_error.errors.iter().map(format_error).collect::<Vec<String>>().join(", "))
}

/// Parse a string into a list of instructions.
///
/// The instructions are not validated and may have invalid names and operand types.
pub fn parse(input: &str) -> Result<Vec<Instruction>, String> {
    match spaces().with(many(parser(instruction)).skip(eof())).parse(State::new(input)) {
        Ok((insts, _)) => Ok(insts),
        Err(err) => Err(format_parse_error(err)),
    }
}

#[cfg(test)]
mod tests {
    use combine::{Parser, parser};
    use super::{ident, integer, register, operand, instruction, Operand, Instruction};

    #[test]
    fn test_ident() {
        assert_eq!(parser(ident).parse("nop"), Ok(("nop".to_string(), "")));
        assert_eq!(parser(ident).parse("add32"), Ok(("add32".to_string(), "")));
        assert_eq!(parser(ident).parse("add32*"),
                   Ok(("add32".to_string(), "*")));
    }

    #[test]
    fn test_integer() {
        assert_eq!(parser(integer).parse("0"), Ok((0, "")));
        assert_eq!(parser(integer).parse("42"), Ok((42, "")));
        assert_eq!(parser(integer).parse("+42"), Ok((42, "")));
        assert_eq!(parser(integer).parse("-42"), Ok((-42, "")));
        assert_eq!(parser(integer).parse("0x0"), Ok((0, "")));
        assert_eq!(parser(integer).parse("0x123456789abcdef0"),
                   Ok((0x123456789abcdef0, "")));
        assert_eq!(parser(integer).parse("-0x1f"), Ok((-31, "")));
    }

    #[test]
    fn test_register() {
        assert_eq!(parser(register).parse("r0"), Ok((0, "")));
        assert_eq!(parser(register).parse("r15"), Ok((15, "")));
    }

    #[test]
    fn test_operand() {
        assert_eq!(parser(operand).parse("r0"), Ok((Operand::Register(0), "")));
        assert_eq!(parser(operand).parse("r15"),
                   Ok((Operand::Register(15), "")));
        assert_eq!(parser(operand).parse("0"), Ok((Operand::Integer(0), "")));
        assert_eq!(parser(operand).parse("42"), Ok((Operand::Integer(42), "")));
        assert_eq!(parser(operand).parse("[r1]"),
                   Ok((Operand::Memory(1, 0), "")));
        assert_eq!(parser(operand).parse("[r3+5]"),
                   Ok((Operand::Memory(3, 5), "")));
        assert_eq!(parser(operand).parse("[r3+0x1f]"),
                   Ok((Operand::Memory(3, 31), "")));
        assert_eq!(parser(operand).parse("[r3-0x1f]"),
                   Ok((Operand::Memory(3, -31), "")));
    }

    #[test]
    fn test_instruction() {
        assert_eq!(parser(instruction).parse("exit"),
                   Ok((Instruction {
                           name: "exit".to_string(),
                           operands: vec![],
                       },
                       "")));

        assert_eq!(parser(instruction).parse("call 2"),
                   Ok((Instruction {
                           name: "call".to_string(),
                           operands: vec![Operand::Integer(2)],
                       },
                       "")));

        assert_eq!(parser(instruction).parse("addi r1, 2"),
                   Ok((Instruction {
                           name: "addi".to_string(),
                           operands: vec![Operand::Register(1), Operand::Integer(2)],
                       },
                       "")));

        assert_eq!(parser(instruction).parse("ldxb r2, [r1+12]"),
                   Ok((Instruction {
                           name: "ldxb".to_string(),
                           operands: vec![Operand::Register(2), Operand::Memory(1, 12)],
                       },
                       "")));

        assert_eq!(parser(instruction).parse("lsh r3, 0x8"),
                   Ok((Instruction {
                           name: "lsh".to_string(),
                           operands: vec![Operand::Register(3), Operand::Integer(8)],
                       },
                       "")));

        assert_eq!(parser(instruction).parse("jne r3, 0x8, +37"),
                   Ok((Instruction {
                           name: "jne".to_string(),
                           operands: vec![Operand::Register(3),
                                          Operand::Integer(8),
                                          Operand::Integer(37)],
                       },
                       "")));

        // Whitespace between operands is optional.
        assert_eq!(parser(instruction).parse("jne r3,0x8,+37"),
                   Ok((Instruction {
                           name: "jne".to_string(),
                           operands: vec![Operand::Register(3),
                                          Operand::Integer(8),
                                          Operand::Integer(37)],
                       },
                       "")));
    }

}
