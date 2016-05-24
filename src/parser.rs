// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

use lexer::{Token, Tokenize};

use std::fmt::Debug;
use std::collections::VecDeque;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Parser {
    stack: Vec<Token>,
    tstack: Vec<Token>,
    regset: Option<HashSet<String>>,
    tokens: Option<VecDeque<Token>>,
    // Allow access for the consumer to set these. If these are set, then the parser automatically
    // returns the value of old, cur and lastsz when required rather than returning the tokens to
    // indicate the same.
    pub eold: Option<Token>,
    pub eold_: Option<Token>,
    pub ecur: Option<Token>,
    pub lastsz: Option<Token>,
}

pub trait Parse {
	type InType: Clone + Debug + PartialEq;
	type OutType: Clone + Debug;

    fn parse<S, T>(&mut self, S) -> Option<Self::OutType>
        where S: AsRef<str>,
              T: Tokenize<Token = Self::InType>;

    fn fetch_operands(&mut self,
                      t: &Self::InType)
                      -> (Option<Self::OutType>, Option<Self::OutType>);

    fn push(&mut self, t: Self::InType);
}

impl Parse for Parser {
    type InType = Token;
    type OutType = Token;

    fn parse<S, T>(&mut self, esil: S) -> Option<Self::OutType>
        where S: AsRef<str>,
              T: Tokenize<Token = Self::InType>
    {
        // TODO: Add notes about mechanism.
        if self.tokens.is_none() {
            self.tokens = Some(T::tokenize(esil));
        }

        while let Some(token) = self.tokens.as_mut().unwrap().pop_front() {
            match token {
                // Esil Internal Vars
                Token::IZero(_) |
                Token::ICarry(_) |
                Token::IParity(_) |
                Token::IOverflow(_) |
                Token::ISign(_) |
                Token::IBorrow(_) |
                Token::ISize(_) |
                Token::IAddress(_) => {
                    let mut internal_q = self.evaluate_internal(&token);
                    while let Some(i) = internal_q.pop_back() {
                        self.tokens.as_mut().map(|v| v.push_front(i));
                    }
                }
                // Esil Operands
                Token::EConstant(_) |
                Token::EIdentifier(_) |
                Token::ECur |
                Token::EOld |
                Token::EOld_ |
                Token::ELastsz => {
                    self.push(token);

                }
                // Parser Instructions.
                Token::PCopy(ref n) => {
                    // Copy 'n' elements from esil stack onto tstack.
                    // _Maintains_ order.
                    let len = self.stack.len();
                    if *n > len {
                        panic!("Request to `PCopy` too many elements!");
                    }
                    self.tstack.extend((&self.stack[len - n..]).iter().cloned());
                }
                Token::PPop(ref n) => {
                    // Pops 'n' elements from the tstack to the esil stack.
                    // _Maintains_ order
                    let len = self.tstack.len();
                    if *n > len {
                        panic!("Request to `PPop` too many elements!");
                    }
                    self.stack.extend((&self.tstack[len - n..]).iter().cloned());
                    self.tstack.truncate(len - n);
                }
                // Not in use _yet_.
                Token::PSync => unimplemented!(),
                // Invalid. Let the Evaluator decide what to do with it.
                // Esil Opcodes. Return to the Evaluator.
                _ => {
                    return Some(token);
                }
            }
        }
        // This means that the parser is empty and there are no more tokens
        // to be processed. So we set tokens to None and return None.
        self.tokens = None;
        None
    }

    fn push(&mut self, t: Self::InType) {
        self.stack.push(t);
    }

    // TODO: Think about changing this to a result type rather than option.
    fn fetch_operands(&mut self, t: &Token) -> (Option<Token>, Option<Token>) {
        if t.is_binary() {
            (self.pop_op(), self.pop_op())
        } else if t.is_unary() {
            (self.pop_op(), None)
        } else if t.is_arity_zero() {
            (None, None)
        } else if !t.is_implemented() {
            unimplemented!();
        } else {
            panic!("Invalid esil opcode!");
        }
    }
}

// Implementation of the parser where the input type is lexer::Token
impl Parser {
    pub fn init(regset: Option<HashSet<String>>) -> Parser {
        Parser {
            stack: Vec::new(),
            tstack: Vec::new(),
            regset: regset,
            tokens: None,
            eold: None,
            eold_: None,
            ecur: None,
            lastsz: None,
        }
    }

    fn get_meta(&self, t: Token) -> Token {
        match t {
            Token::EOld => self.eold.as_ref().unwrap_or(&t),
            Token::EOld_ => self.eold_.as_ref().unwrap_or(&t),
            Token::ECur => self.ecur.as_ref().unwrap_or(&t),
            Token::ELastsz => self.lastsz.as_ref().unwrap_or(&t),
            _ => panic!("Improper usage of function."),
        }
        .clone()
    }

    fn evaluate_internal(&self, t: &Token) -> VecDeque<Token> {
        let mut result = VecDeque::new();
        // Set the lower most `bit` bits to 1.
        let genmask = |bit: u64| {
            // ( 1 << bit ) - 1
            [Token::EConstant(1),
             Token::EConstant(bit),
             Token::EConstant(1),
             Token::ELsl,
             Token::ESub]
        };

        // Initialize esil vars.
        let esil_old = self.get_meta(Token::EOld);
        let esil_old_ = self.get_meta(Token::EOld_);
        let esil_cur = self.get_meta(Token::ECur);
        let lastsz = match self.get_meta(Token::ELastsz) {
            Token::ELastsz => panic!("lastsz unset!"),
            Token::EConstant(size) => size,
            _ => panic!("lastsz cannot be something other than a constant!"),
        };

        match *t {
            Token::IZero(_) => {
                result.extend(genmask(lastsz).iter().cloned());
                result.extend([esil_cur, Token::EAnd, Token::EConstant(0), Token::ECmp]
                                  .iter()
                                  .cloned())
            }
            Token::ICarry(_bit) => {
                result.extend([esil_cur, esil_old, Token::EGt].iter().cloned());
            }
            Token::IParity(_) => {
                // Parity flag computation as described in:
                //   - https://graphics.stanford.edu/~seander/bithacks.html#ParityWith64Bits
                let c1: u64 = 0x0101010101010101;
                let c2: u64 = 0x8040201008040201;
                let c3: u64 = 0x1FF;
                result.extend([Token::EConstant(1),
                               Token::EConstant(c3),
                               Token::EConstant(c2),
                               Token::EConstant(c1),
                               esil_cur,
                               Token::EMul,
                               Token::EAnd,
                               Token::EMod,
                               Token::EAnd]
                                  .iter()
                                  .cloned());
            }
            Token::IOverflow(bit) => {
                // of = ((((~eold ^ eold_) & (enew ^ eold)) >> (lastsz - 1)) & 1) == 1
                result.extend([Token::EConstant(1),
                               Token::EConstant(1),
                               Token::EConstant(lastsz - 1),
                               esil_old.clone(),
                               esil_cur,
                               Token::EXor,
                               esil_old_,
                               esil_old.clone(),
                               Token::ENeg,
                               Token::EXor,
                               Token::EAnd,
                               Token::ELsr,
                               Token::EAnd,
                               Token::ECmp]
                                  .iter()
                                  .cloned());
            }
            Token::ISign(_) => {
                result.extend([Token::EConstant(1),
                               self.get_meta(Token::ELastsz),
                               Token::ESub,
                               self.get_meta(Token::ECur),
                               Token::ELsr]
                                  .iter()
                                  .cloned());
            }
            Token::IBorrow(_bit) => {
                result.extend([esil_cur, esil_old, Token::ELt].iter().cloned());
            }
            Token::ISize(_) => {
                result.push_front(Token::EConstant(64));
            }
            Token::IAddress(_) => {
                result.push_front(Token::EAddress);
            }
            _ => unreachable!(),
        }
        result
    }

    fn pop_op(&mut self) -> Option<Token> {
        if self.stack.len() > 0 {
            self.stack.pop()
        } else {
            panic!("Insufficient operands!");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lexer::*;

    // Construct a prefix expression.
    struct ExpressionConstructor;
    impl ExpressionConstructor {
        fn get_inner_or_null(t: Option<Token>) -> String {
            if t.is_none() {
                return "-".to_owned();
            }
            match t.unwrap() {
                Token::EIdentifier(s) => s,
                Token::EConstant(c) => format!("{:#X}", c),
                Token::EOld => "rax_old".to_owned(),
                Token::EOld_ => "rbx_old".to_owned(),
                Token::ECur => "rax_cur".to_owned(),
                _ => "".to_owned(),
            }
        }

        pub fn run<T: AsRef<str>>(esil: T) -> String {
            let mut p = Parser::init(None);
            p.lastsz = Some(Token::EConstant(64));
            let mut expression = String::new();
            while let Some(ref token) = p.parse::<_, Tokenizer>(&esil) {
                let (lhs, rhs) = p.fetch_operands(token);
                let lhs = ExpressionConstructor::get_inner_or_null(lhs);
                let rhs = ExpressionConstructor::get_inner_or_null(rhs);
                expression = format!("({:?}  {}, {})", token, lhs, rhs);
                p.push(Token::EIdentifier(expression.clone()));
            }
            expression
        }
    }

    macro_rules! construct {
        ($s: expr) => {
            ExpressionConstructor::run($s)
        }
    }

    #[test]
    fn parser_basic_1() {
        let expression = ExpressionConstructor::run("6,rax,+=");
        assert_eq!("(EEq  rax, (EAdd  rax, 0x6))", expression);
    }

    #[test]
    fn parser_zf() {
        let expression = ExpressionConstructor::run("$z,zf,=");
        assert_eq!("(EEq  zf, (ECmp  0x0, (EAnd  rax_cur, (ESub  (ELsl  0x1, 0x40), 0x1))))", expression);
    }

    #[test]
    fn parser_pf() {
        let expression = ExpressionConstructor::run("$p,pf,=");
        assert_eq!("(EEq  pf, (EAnd  (EMod  (EAnd  (EMul  rax_cur, 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))", expression);
    }

    #[test]
    fn parser_cf() {
        let expression = ExpressionConstructor::run("$c64,cf,=");
        let expected = "(EEq  cf, (EGt  rax_old, rax_cur))";
        assert_eq!(expected, expression);
    }

    #[test]
    fn parser_of() {
        // of = ((((~eold ^ eold_) & (enew ^ eold)) >> (lastsz - 1)) & 1) == 1
        let expression = ExpressionConstructor::run("$o,of,=");
        let expected = "(EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  rax_old, -), rbx_old), (EXor  rax_cur, rax_old)), 0x3F), 0x1), 0x1))";
        assert_eq!(expected, expression);
    }

    #[test]
    fn parser_bf() {
        let expression = ExpressionConstructor::run("$b64,cf,=");
        let expected = "(EEq  cf, (ELt  rax_old, rax_cur))";
        assert_eq!(expected, expression);
    }

    #[test]
    fn parser_composite_1() {
        assert_eq!("(EEq  rax, (ESub  rax, 0x1))", construct!("rax,--="));
    }

    #[test]
    fn parser_composite_2() {
        assert_eq!("(EPoke(64)  0x800, (EAnd  (EPeek(64)  0x800, -), rax))",
                   construct!("rax,0x800,&=[8]"));
    }

    #[test]
    fn parser_composite_3() {
        assert_eq!("(EPoke(64)  0x800, (ESub  (EPeek(64)  0x800, -), 0x1))",
                   construct!("rax,0x800,--=[8]"));
    }
}
