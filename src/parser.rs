// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

use lexer::{Token, Tokenize};
use lexer::USE_DEFAULT_SIZE;

use std::fmt::Debug;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct Parser {
    stack: Vec<Token>,
    tstack: Vec<Token>,
    tokens: Option<VecDeque<Token>>,
    // Number of instructions to ignore setting of ESIL variables, i.e.,
    // esil_cur, esil_old_, esil_old, lastsz.
    skip_esil_set: usize,
    // Map of identifiers and their sizes. Used to automatically set lastsz correctly.
    ident_map: Option<HashMap<String, u64>>,
    // Default size for the arch. Used if the identifier is not found in the ident_map.
    default_size: u64,
    // Last ESIL operation that was returned to the consumer.
    last_op: Option<Token>,
    // Last two pop operations performed by the consumer.
    last_pop: (Option<Token>, Option<Token>),
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
            self.skip_esil_set = 0;
            self.tokens = Some(T::tokenize(esil));
        }

        // Set ESIL meta-variable
        if self.skip_esil_set == 0 {
            if let Some(ref token) = self.last_op {
                if token.should_set_vars() && token.updates_result() {
                    self.ecur = self.stack.last().cloned();
                }
            }
        }

        while let Some(mut token) = self.tokens.as_mut().unwrap().pop_front() {
            match token {
                // Esil Internal Vars
                Token::IZero(_) |
                Token::ICarry(_) |
                Token::IParity(_) |
                Token::IOverflow(_) |
                Token::ISign(_) |
                Token::IBorrow(_) |
                Token::ISize(_) |
                Token::IConstant(_) |
                Token::IAddress(_) => {
                    let mut internal_q = self.evaluate_internal(&token);
                    //self.skip_esil_set += internal_q.len() + 1;
                    while let Some(i) = internal_q.pop_back() {
                        // count the number of operations to skip for.
                        self.tokens.as_mut().map(|v| v.push_front(i));
                    }
                }
                // Esil Operands
                Token::EConstant(_) |
                Token::EIdentifier(_) |
                Token::ECur |
                Token::EOld |
                Token::EOld_ |
                Token::ELastsz |
                Token::EEntry(_, _) => {
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
                Token::EPop => {
                    if self.stack.pop().is_none() {
                        panic!("Invalid ESIL pop!");
                    }
                }
                Token::EDup => {
                    let top = self.stack.last().cloned().unwrap();
                    self.push(top);
                }
                // Invalid. Let the Evaluator decide what to do with it.
                // Esil Opcodes. Return to the Evaluator.
                _ => {
                    // Handle default size for EPoke and EPeek.
                    // _bit == 0 means esil-rs will use the default_size.
                    match token {
                        Token::EPeek(ref mut _bit) |
                        Token::EPoke(ref mut _bit) => {
                            if *_bit == USE_DEFAULT_SIZE {
                                *_bit = self.default_size as u8;
                            }
                        }
                        _ => {  }
                    }
                    if self.skip_esil_set == 0 {
                        self.last_op = Some(token.clone());
                    } else {
                        self.skip_esil_set -= 1;
                    }
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

    fn fetch_operands(&mut self, t: &Token) -> (Option<Token>, Option<Token>) {
        let result = if t.is_binary() {
            (self.pop_op(), self.pop_op())
        } else if t.is_unary() {
            (self.pop_op(), None)
        } else if t.is_arity_zero() {
            (None, None)
        } else if !t.is_implemented() {
            unimplemented!();
        } else {
            panic!("Invalid esil opcode: {:?}!", t);
        };

        if self.skip_esil_set == 0 {
            if t.should_set_vars() {
                // For ECmp, last_pop should be the operands we to the ECmp.
                if t.updates_result() {
                    self.last_pop = result.clone();
                }
                self.eold = self.last_pop.0.clone();
                self.eold_ = self.last_pop.1.clone();
                if !t.updates_result() {
                    self.ecur = result.1.clone();
                }
                self.lastsz = Some(Token::EConstant(match self.eold {
                    None => self.default_size,
                    Some(Token::EIdentifier(ref s)) => {
                        if let Some(ref map) = self.ident_map {
                            map.get(s).cloned().unwrap_or(self.default_size)
                        } else {
                            self.default_size
                        }
                    }
                    Some(Token::EConstant(_)) => self.default_size,
                    Some(Token::EEntry(_, n)) => n.unwrap_or(self.default_size),
                    _ => unreachable!(),
                }));
            } else {
                self.last_pop = result.clone();
            }
        }

        result
    }
}

// Implementation of the parser where the input type is lexer::Token
impl Parser {
    pub fn init(ident_map: Option<HashMap<String, u64>>, default_size: Option<u64>) -> Parser {
        Parser {
            stack: Vec::new(),
            tstack: Vec::new(),
            ident_map: ident_map,
            skip_esil_set: 0,
            default_size: default_size.unwrap_or(64),
            last_op: None,
            last_pop: (None, None),
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

    fn evaluate_internal(&mut self, t: &Token) -> VecDeque<Token> {
        let mut result = VecDeque::new();
        // Set the lower most `bit` bits to 1.
        let genmask = |bit: u64| {
            // ( 1 << bit ) - 1
            if bit == 64 {
                [Token::EConstant(u64::max_value())]
            } else {
                [Token::EConstant((1 << bit) - 1)]
            }
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

        // NOTE: self.skip_esil_set must be set to the number of operations that you are
        // introducing as a part of the internal evaluation. This is also equal to the number of
        // tokens that will be returned from the parser to the consumer.
        match *t {
            Token::IZero(_) => {
                result.extend(genmask(lastsz).iter().cloned());
                result.extend([esil_cur, Token::EAnd, Token::EConstant(1), Token::EXor]
                                  .iter()
                                  .cloned());
                self.skip_esil_set = 4;
            }
            Token::ICarry(_bit) => {
                result.extend([esil_cur, esil_old, Token::EGt].iter().cloned());
                self.skip_esil_set = 3;
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
                               Token::EConstant(0xFF),
                               esil_cur,
                               Token::EAnd,
                               Token::EMul,
                               Token::EAnd,
                               Token::EMod,
                               Token::EAnd]
                                  .iter()
                                  .cloned());
                self.skip_esil_set = 7;
            }
            Token::IOverflow(_bit) => {
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
                self.skip_esil_set = 9;
            }
            Token::ISign(_) => {
                result.extend([Token::EConstant(1),
                               self.get_meta(Token::ELastsz),
                               Token::ESub,
                               self.get_meta(Token::ECur),
                               Token::ELsr]
                                  .iter()
                                  .cloned());
                self.skip_esil_set = 4;
            }
            Token::IBorrow(_bit) => {
                result.extend([esil_cur, esil_old, Token::ELt].iter().cloned());
                self.skip_esil_set = 3;
            }
            Token::ISize(_) => {
                result.push_front(Token::EConstant(self.default_size));
                self.skip_esil_set = 2;
            }
            Token::IAddress(_) => {
                result.push_front(Token::EAddress);
                self.skip_esil_set = 2;
            }
            Token::IConstant(n) => {
                result.push_front(Token::EConstant(n));
                self.skip_esil_set = 2;
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

    use std::collections::HashMap;

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

        pub fn run<T: AsRef<str>>(esil: T, parser: Option<&mut Parser>) -> String {
            let mut pp = Parser::init(None, None);
            let p = parser.unwrap_or(&mut pp);
            p.lastsz = Some(Token::EConstant(64));
            let mut expression = String::new();
            while let Some(ref token) = p.parse::<_, Tokenizer>(&esil) {
                let (lhs, rhs) = p.fetch_operands(token);
                let lhs = ExpressionConstructor::get_inner_or_null(lhs);
                let rhs = ExpressionConstructor::get_inner_or_null(rhs);
                expression = format!("({:?}  {}, {})", token, lhs, rhs);
                p.push(Token::EIdentifier(expression.clone()));
            }

            expression.clear();
            for expr in &p.stack {
                if let &Token::EIdentifier(ref s) = expr {
                    expression.push_str(s);
                }
            }
            expression
        }
    }

    fn sample_regset() -> HashMap<String, u64> {
        let mut regset = HashMap::new();
        regset.insert("rax".to_owned(), 64);
        regset.insert("rbx".to_owned(), 64);
        regset.insert("rcx".to_owned(), 64);
        regset.insert("eax".to_owned(), 32);
        regset.insert("ebx".to_owned(), 32);
        regset.insert("ecx".to_owned(), 32);
        regset.insert("zf".to_owned(), 1);
        regset.insert("pf".to_owned(), 1);
        regset.insert("cf".to_owned(), 1);
        regset.insert("of".to_owned(), 1);
        regset.insert("sf".to_owned(), 1);
        regset
    }

    macro_rules! construct {
        ($s: expr) => {
            ExpressionConstructor::run($s, None)
        }
    }

    #[test]
    fn parser_basic_1() {
        let expression = construct!("6,rax,+=");
        assert_eq!("(EEq  rax, (EAdd  rax, 0x6))", expression);
    }

    #[test]
    fn parser_zf() {
        let expression = construct!("$z,zf,=");
        assert_eq!("(EEq  zf, (EXor  0x1, (EAnd  rax_cur, 0xFFFFFFFFFFFFFFFF)))",
                   expression);
    }

    #[test]
    fn parser_pf() {
        let expression = construct!("$p,pf,=");
        assert_eq!("(EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  rax_cur, 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))", expression);
    }

    #[test]
    fn parser_cf() {
        let expression = construct!("$c64,cf,=");
        let expected = "(EEq  cf, (EGt  rax_old, rax_cur))";
        assert_eq!(expected, expression);
    }

    #[test]
    fn parser_of() {
        // of = ((((~eold ^ eold_) & (enew ^ eold)) >> (lastsz - 1)) & 1) == 1
        let expression = construct!("$o,of,=");
        let expected = "(EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  rax_old, -), rbx_old), (EXor  rax_cur, rax_old)), 0x3F), 0x1), 0x1))";
        assert_eq!(expected, expression);
    }

    #[test]
    fn parser_bf() {
        let expression = construct!("$b64,cf,=");
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
                   construct!("0x800,--=[8]"));
    }

    #[test]
    fn parser_composite_4() {
        assert_eq!("(EEq  rax, (EAdd  rax, 0x1))", construct!("rax,++="));
    }

    #[test]
    fn parser_test_esil_vars() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr = ExpressionConstructor::run("rbx,rax,+=,$0,cf,=", Some(&mut parser));
        assert_eq!(parser.eold, Some(Token::EIdentifier("rax".to_owned())));
        assert_eq!(parser.eold_, Some(Token::EIdentifier("rbx".to_owned())));
        assert_eq!(parser.ecur,
                   Some(Token::EIdentifier("(EAdd  rax, rbx)".to_owned())));
        let expected = "(EEq  rax, (EAdd  rax, rbx))(EEq  cf, 0x0)";
        assert_eq!(expected, &expr);
    }

    #[test]
    fn parser_x86_add64() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr = ExpressionConstructor::run("rbx,rax,+=,$o,of,=,$s,sf,=,$z,zf,=,$c63,cf,=,$p,pf,=",
                                              Some(&mut parser));

        let expected = "(EEq  rax, (EAdd  rax, rbx))\
                        (EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  rax, -), rbx), (EXor  (EAdd  rax, rbx), rax)), 0x3F), 0x1), 0x1))\
                        (EEq  sf, (ELsr  (EAdd  rax, rbx), (ESub  0x40, 0x1)))\
                        (EEq  zf, (EXor  0x1, (EAnd  (EAdd  rax, rbx), 0xFFFFFFFFFFFFFFFF)))\
                        (EEq  cf, (EGt  rax, (EAdd  rax, rbx)))\
                        (EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  (EAdd  rax, rbx), 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))";

        assert_eq!(expected, &expr);
    }

    #[test]
    fn parser_x86_add32() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr = ExpressionConstructor::run("ebx,eax,+=,$o,of,=,$s,sf,=,$z,zf,=,$c31,cf,=,$p,pf,=",
                                              Some(&mut parser));

        let expected = "(EEq  eax, (EAdd  eax, ebx))\
                        (EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  eax, -), ebx), (EXor  (EAdd  eax, ebx), eax)), 0x1F), 0x1), 0x1))\
                        (EEq  sf, (ELsr  (EAdd  eax, ebx), (ESub  0x20, 0x1)))\
                        (EEq  zf, (EXor  0x1, (EAnd  (EAdd  eax, ebx), 0xFFFFFFFF)))\
                        (EEq  cf, (EGt  eax, (EAdd  eax, ebx)))\
                        (EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  (EAdd  eax, ebx), 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))";

        assert_eq!(expected, &expr);
    }

    #[test]
    fn parser_x86_cmp() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr =
            ExpressionConstructor::run("0,rax,rax,&,==,$0,of,=,$s,sf,=,$z,zf,=,$0,cf,=,$p,pf,=",
                                       Some(&mut parser));

        let expected = "(ECmp  (EAnd  rax, rax), 0x0)\
        (EEq  of, 0x0)\
        (EEq  sf, (ELsr  (ECmp  (EAnd  rax, rax), 0x0), (ESub  0x40, 0x1)))\
        (EEq  zf, (EXor  0x1, (EAnd  (ECmp  (EAnd  rax, rax), 0x0), 0xFFFFFFFFFFFFFFFF)))\
        (EEq  cf, 0x0)\
        (EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  (ECmp  (EAnd  rax, rax), 0x0), 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))";

        assert_eq!(expected, &expr);
    }

    #[test]
    fn parser_lt_gt() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let _expr = ExpressionConstructor::run("rax,rbx,<", Some(&mut parser));

        assert_eq!(parser.eold, Some(Token::EIdentifier("rbx".to_owned())));
        assert_eq!(parser.eold_, Some(Token::EIdentifier("rax".to_owned())));
        assert_eq!(parser.ecur,
                   Some(Token::EIdentifier("(ELt  rbx, rax)".to_owned())));
        assert_eq!(parser.lastsz, Some(Token::EConstant(64)));

        let _expr = ExpressionConstructor::run("rbx,rax,>", Some(&mut parser));

        assert_eq!(parser.eold, Some(Token::EIdentifier("rax".to_owned())));
        assert_eq!(parser.eold_, Some(Token::EIdentifier("rbx".to_owned())));
        assert_eq!(parser.ecur,
                   Some(Token::EIdentifier("(EGt  rax, rbx)".to_owned())));
        assert_eq!(parser.lastsz, Some(Token::EConstant(64)));
    }

    #[test]
    fn parser_x86_adc() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr =
            ExpressionConstructor::run("cf,eax,+,eax,+=,$o,of,=,$s,sf,=,$z,zf,=,$c31,cf,=,$p,pf,=",
                                       Some(&mut parser));

        let expected = "(EEq  eax, (EAdd  eax, (EAdd  eax, cf)))\
                        (EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  eax, -), (EAdd  eax, cf)), (EXor  (EAdd  eax, (EAdd  eax, cf)), eax)), 0x1F), 0x1), 0x1))\
                        (EEq  sf, (ELsr  (EAdd  eax, (EAdd  eax, cf)), (ESub  0x20, 0x1)))\
                        (EEq  zf, (EXor  0x1, (EAnd  (EAdd  eax, (EAdd  eax, cf)), 0xFFFFFFFF)))\
                        (EEq  cf, (EGt  eax, (EAdd  eax, (EAdd  eax, cf))))\
                        (EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  (EAdd  eax, (EAdd  eax, cf)), 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))";

        assert_eq!(expected, &expr);
    }

    #[test]
    fn parser_multiple_insts() {
        let regset = sample_regset();
        let mut parser = Parser::init(Some(regset), Some(64));
        let expr = ExpressionConstructor::run("cf,eax,+,eax,+=,$o,of,=,$s,sf,=,$z,zf,=,$c31,cf,=,$p,pf,=",
                                       Some(&mut parser));

        let expected = "(EEq  eax, (EAdd  eax, (EAdd  eax, cf)))\
                        (EEq  of, (ECmp  (EAnd  (ELsr  (EAnd  (EXor  (ENeg  eax, -), (EAdd  eax, cf)), (EXor  (EAdd  eax, (EAdd  eax, cf)), eax)), 0x1F), 0x1), 0x1))\
                        (EEq  sf, (ELsr  (EAdd  eax, (EAdd  eax, cf)), (ESub  0x20, 0x1)))\
                        (EEq  zf, (EXor  0x1, (EAnd  (EAdd  eax, (EAdd  eax, cf)), 0xFFFFFFFF)))\
                        (EEq  cf, (EGt  eax, (EAdd  eax, (EAdd  eax, cf))))\
                        (EEq  pf, (EAnd  (EMod  (EAnd  (EMul  (EAnd  (EAdd  eax, (EAdd  eax, cf)), 0xFF), 0x101010101010101), 0x8040201008040201), 0x1FF), 0x1))";

        assert_eq!(expected, &expr);
        assert_eq!(parser.skip_esil_set, 1);

        let _ = ExpressionConstructor::run("rax,rbx,-=,$0,cf,=", Some(&mut parser));
        assert_eq!(parser.eold, Some(Token::EIdentifier("rbx".to_owned())));
        assert_eq!(parser.eold_, Some(Token::EIdentifier("rax".to_owned())));
        assert_eq!(parser.ecur, Some(Token::EIdentifier("(ESub  rbx, rax)".to_owned())));
        assert_eq!(parser.skip_esil_set, 1);
    }

    #[test]
    fn parser_follow_false() {
        // TODO
    }

    #[test]
    fn parser_follow_true() {
        // TODO
    }
}
