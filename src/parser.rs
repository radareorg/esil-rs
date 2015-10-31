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
                Token::EConstant(_) | Token::EIdentifier(_) => {
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
        }
    }

    fn evaluate_internal(&self, t: &Token) -> VecDeque<Token> {
        let mut result = VecDeque::new();
        let genmask = |bit: u8| {
            // ( 2 << bit ) - 1
            [Token::EConstant(1),
             Token::EConstant(bit as u64),
             Token::EConstant(2),
             Token::ELsl,
             Token::ESub]
        };
        match *t {
            Token::IZero(_) => {
                result.extend([Token::ECur, Token::EConstant(0), Token::ECmp].iter().cloned())
            }
            Token::ICarry(_bit) => {
                let bit = _bit & 0x3F;
                let x = [Token::PCopy(1),
                         Token::ECur,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::PPop(1),
                         Token::EOld,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::EGt];
                result.extend(genmask(bit).iter().cloned());
                result.extend(x.iter().cloned());
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
                               Token::ECur,
                               Token::EMul,
                               Token::EAnd,
                               Token::EMod,
                               Token::EAnd]
                                  .iter()
                                  .cloned());
            }
            Token::IOverflow(_bit) => {
                // FIXME: This may be potentially buggy and may have to be replaced by using
                // lastsz instead of bit (as that is the right thing to do).
                let carry_in_bit = (_bit - 2) & 0x3F;
                let carry_out_bit = (_bit - 1) & 0x3F;
                let x = [Token::PCopy(1),
                         Token::ECur,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::PPop(1),
                         Token::EOld,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::EGt];
                result.extend(genmask(carry_in_bit).iter().cloned());
                result.extend(x.iter().cloned());
                result.extend(genmask(carry_out_bit).iter().cloned());
                result.extend(x.iter().cloned());
                result.extend([Token::EXor].iter().cloned());
            }
            Token::ISign(_) => {
                result.extend([Token::EConstant(1),
                               Token::EConstant(1),
                               Token::EConstant(0x1F),
                               Token::ECur,
                               Token::ELsr,
                               Token::EAnd,
                               Token::ECmp]
                                  .iter()
                                  .cloned());
            }
            Token::IBorrow(_bit) => {
                let bit = ((_bit & 0x3F) + 0x3F) & 0x3F;
                let x = [Token::PCopy(1),
                         Token::ECur,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::PPop(1),
                         Token::EOld,
                         Token::PPop(1),
                         Token::EAnd,
                         Token::ELt];
                result.extend(genmask(bit).iter().cloned());
                result.extend(x.iter().cloned());
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
    use std::collections::{HashMap, VecDeque};

    struct Evaluator<P: Parse + Clone> {
        instructions: VecDeque<String>,
        values: HashMap<String, u64>,
        parser: P,
    }
    // TODO: Tests using a VM emulator
}
