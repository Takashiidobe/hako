use std::collections::HashMap;
use std::io::{self, BufRead, Write};

pub fn run(mut input: impl BufRead, out: &mut impl Write, args: &[String]) -> io::Result<()> {
    let mut calc = Calc::new();
    if args.is_empty() {
        repl(&mut input, out, &mut calc)
    } else {
        let value = calc.eval_line(&args.join(" ")).map_err(io::Error::other)?;
        writeln!(out, "{}", format_number(value))
    }
}

struct Calc {
    vars: HashMap<String, f64>,
}

impl Calc {
    fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    fn eval_line(&mut self, line: &str) -> Result<f64, String> {
        let tokens = lex(line)?;
        let mut parser = Parser::new(&tokens, &self.vars);
        if parser.take_let() {
            let name = parser.take_ident()?;
            parser.expect(TokenKind::Equal)?;
            let value = parser.parse_expr(0)?;
            parser.expect(TokenKind::Eof)?;
            self.vars.insert(name, value);
            Ok(value)
        } else {
            let value = parser.parse_expr(0)?;
            parser.expect(TokenKind::Eof)?;
            Ok(value)
        }
    }
}

fn repl(input: &mut impl BufRead, out: &mut impl Write, calc: &mut Calc) -> io::Result<()> {
    let mut line = String::new();
    loop {
        write!(out, "> ")?;
        out.flush()?;
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed == ":quit" || trimmed == ":q" {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }
        match calc.eval_line(trimmed) {
            Ok(value) => writeln!(out, "{}", format_number(value))?,
            Err(err) => writeln!(out, "error: {err}")?,
        }
    }
    Ok(())
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.is_finite() {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(f64),
    Ident(String),
    Let,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Equal,
    LParen,
    RParen,
    Eof,
}

#[derive(Copy, Clone, PartialEq)]
enum TokenKind {
    Equal,
    RParen,
    Eof,
}

fn lex(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.peek().copied() {
        match ch {
            ' ' | '\t' | '\r' | '\n' => {
                chars.next();
            }
            '+' => {
                chars.next();
                tokens.push(Token::Plus);
            }
            '-' => {
                chars.next();
                tokens.push(Token::Minus);
            }
            '*' => {
                chars.next();
                tokens.push(Token::Star);
            }
            '/' => {
                chars.next();
                tokens.push(Token::Slash);
            }
            '%' => {
                chars.next();
                tokens.push(Token::Percent);
            }
            '^' => {
                chars.next();
                tokens.push(Token::Caret);
            }
            '=' => {
                chars.next();
                tokens.push(Token::Equal);
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '0'..='9' => tokens.push(lex_number(&mut chars)?),
            '.' if chars.clone().nth(1).is_some_and(|c| c.is_ascii_digit()) => {
                tokens.push(lex_number(&mut chars)?);
            }
            'a'..='z' | 'A'..='Z' | '_' => tokens.push(lex_ident(&mut chars)),
            _ => return Err(format!("unexpected character: {ch}")),
        }
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

fn lex_number(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<Token, String> {
    let mut s = String::new();

    if chars.peek().copied() == Some('0') {
        chars.next();
        match chars.peek().copied() {
            Some('x' | 'X') => {
                chars.next();
                while let Some(ch) = chars.peek().copied() {
                    if ch.is_ascii_hexdigit() {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if s.is_empty() {
                    return Err("expected hex digits".into());
                }
                let value = u64::from_str_radix(&s, 16).map_err(|_| "hex literal too large")?;
                return Ok(Token::Number(value as f64));
            }
            Some('b' | 'B') => {
                chars.next();
                while let Some(ch) = chars.peek().copied() {
                    if ch == '0' || ch == '1' {
                        s.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if s.is_empty() {
                    return Err("expected binary digits".into());
                }
                let value = u64::from_str_radix(&s, 2).map_err(|_| "binary literal too large")?;
                return Ok(Token::Number(value as f64));
            }
            _ => s.push('0'),
        }
    }

    while let Some(ch) = chars.peek().copied() {
        if ch.is_ascii_digit() {
            s.push(ch);
            chars.next();
        } else {
            break;
        }
    }

    if chars.peek().copied() == Some('.') {
        s.push('.');
        chars.next();
        while let Some(ch) = chars.peek().copied() {
            if ch.is_ascii_digit() {
                s.push(ch);
                chars.next();
            } else {
                break;
            }
        }
    }

    s.parse::<f64>()
        .map(Token::Number)
        .map_err(|_| format!("bad number: {s}"))
}

fn lex_ident(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Token {
    let mut s = String::new();
    while let Some(ch) = chars.peek().copied() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            s.push(ch);
            chars.next();
        } else {
            break;
        }
    }
    if s == "let" {
        Token::Let
    } else {
        Token::Ident(s)
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    vars: &'a HashMap<String, f64>,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token], vars: &'a HashMap<String, f64>) -> Self {
        Self {
            tokens,
            pos: 0,
            vars,
        }
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<f64, String> {
        let mut lhs = match self.next().clone() {
            Token::Number(value) => value,
            Token::Ident(name) => self
                .vars
                .get(&name)
                .copied()
                .ok_or_else(|| format!("unknown variable: {name}"))?,
            Token::Minus => -self.parse_expr(7)?,
            Token::LParen => {
                let value = self.parse_expr(0)?;
                self.expect(TokenKind::RParen)?;
                value
            }
            other => return Err(format!("expected expression, found {}", describe(&other))),
        };

        loop {
            let op = match self.peek() {
                Token::Plus => (3, 4, Op::Add),
                Token::Minus => (3, 4, Op::Sub),
                Token::Star => (5, 6, Op::Mul),
                Token::Slash => (5, 6, Op::Div),
                Token::Percent => (5, 6, Op::Rem),
                Token::Caret => (8, 7, Op::Pow),
                _ => break,
            };
            if op.0 < min_bp {
                break;
            }
            self.next();
            let rhs = self.parse_expr(op.1)?;
            lhs = match op.2 {
                Op::Add => lhs + rhs,
                Op::Sub => lhs - rhs,
                Op::Mul => lhs * rhs,
                Op::Div if rhs == 0.0 => return Err("division by zero".into()),
                Op::Div => lhs / rhs,
                Op::Rem if rhs == 0.0 => return Err("remainder by zero".into()),
                Op::Rem => lhs % rhs,
                Op::Pow => lhs.powf(rhs),
            };
        }

        Ok(lhs)
    }

    fn take_let(&mut self) -> bool {
        if matches!(self.peek(), Token::Let) {
            self.next();
            true
        } else {
            false
        }
    }

    fn take_ident(&mut self) -> Result<String, String> {
        match self.next().clone() {
            Token::Ident(name) => Ok(name),
            other => Err(format!(
                "expected variable name, found {}",
                describe(&other)
            )),
        }
    }

    fn expect(&mut self, kind: TokenKind) -> Result<(), String> {
        let token = self.next().clone();
        let ok = matches!(
            (&token, kind),
            (Token::Equal, TokenKind::Equal)
                | (Token::RParen, TokenKind::RParen)
                | (Token::Eof, TokenKind::Eof)
        );
        if ok {
            Ok(())
        } else {
            Err(format!(
                "expected {}, found {}",
                kind_name(kind),
                describe(&token)
            ))
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn next(&mut self) -> &Token {
        let token = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        self.pos = self.pos.saturating_add(1);
        token
    }
}

enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Pow,
}

fn describe(token: &Token) -> String {
    match token {
        Token::Number(value) => format_number(*value),
        Token::Ident(name) => name.clone(),
        Token::Let => "let".into(),
        Token::Plus => "+".into(),
        Token::Minus => "-".into(),
        Token::Star => "*".into(),
        Token::Slash => "/".into(),
        Token::Percent => "%".into(),
        Token::Caret => "^".into(),
        Token::Equal => "=".into(),
        Token::LParen => "(".into(),
        Token::RParen => ")".into(),
        Token::Eof => "end of input".into(),
    }
}

fn kind_name(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Equal => "=",
        TokenKind::RParen => ")",
        TokenKind::Eof => "end of input",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn evaluates_precedence_and_parentheses() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line("2 + 3 * 4"), Ok(14.0));
        assert_eq!(calc.eval_line("(2 + 3) * 4"), Ok(20.0));
    }

    #[test]
    fn evaluates_unary_remainder_and_power() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line("-2 ^ 3"), Ok(-8.0));
        assert_eq!(calc.eval_line("10 % 4"), Ok(2.0));
    }

    #[test]
    fn keeps_let_bindings() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line("let block = 4096"), Ok(4096.0));
        assert_eq!(calc.eval_line("let pages = 128"), Ok(128.0));
        assert_eq!(calc.eval_line("block * pages"), Ok(524_288.0));
        assert_eq!(calc.eval_line("let block = 2"), Ok(2.0));
        assert_eq!(calc.eval_line("block * pages"), Ok(256.0));
    }

    #[test]
    fn parses_hex_and_binary_literals() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line("0xff + 0b1010"), Ok(265.0));
    }

    #[test]
    fn parses_decimal_literals() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line(".5 + 1.25"), Ok(1.75));
    }

    #[test]
    fn rejects_division_and_remainder_by_zero() {
        let mut calc = Calc::new();
        assert_eq!(calc.eval_line("1 / 0"), Err("division by zero".into()));
        assert_eq!(calc.eval_line("1 % 0"), Err("remainder by zero".into()));
    }

    #[test]
    fn rejects_unknown_vars_and_bad_let_names() {
        let mut calc = Calc::new();
        assert!(calc.eval_line("missing + 1").is_err());
        assert!(calc.eval_line("let 1x = 2").is_err());
    }

    #[test]
    fn run_evaluates_args_once() {
        let mut out = Vec::new();
        assert!(run(Cursor::new(""), &mut out, &["2+2".into()]).is_ok());
        assert_eq!(out, b"4\n");
    }

    #[test]
    fn repl_keeps_bindings_and_continues_after_errors() {
        let input = Cursor::new("let x = 5\nbad + 1\nx * 3\n:q\n");
        let mut out = Vec::new();
        assert!(run(input, &mut out, &[]).is_ok());
        assert_eq!(out, b"> 5\n> error: unknown variable: bad\n> 15\n> ");
    }
}
