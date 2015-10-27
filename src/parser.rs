use ::lexer::{Token, Tokenize};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::collections::HashSet;

pub trait ActionHandler {
    type InType: Clone + Debug + PartialEq;
    type OutType: Clone;

    fn init() -> Self;
    fn evaluate(&mut self, &Self::InType);
    fn results(&mut self) -> Option<Self::OutType>;
}

pub struct Parser<T: ActionHandler> {
    handler: T,
    old: Option<T::InType>,
    new: Option<T::InType>,
    lastsz: usize,
    stack: Vec<T::InType>,
    tstack: Vec<T::InType>,
    regset: Option<HashSet<String>>,
    tokens: Option<VecDeque<T::InType>>
}

// Implementation of the parser where the input type is lexer::Token
impl<T: ActionHandler<InType=Token>> Parser<T> {
    pub fn init(regset: Option<HashSet<String>>) -> Parser<T> {
        let h = T::init();
        Parser {
            handler: h,
            old: None,
            new: None,
            lastsz: 0,
            stack: Vec::new(),
            tstack: Vec::new(),
            regset: regset,
            tokens: None,
        }
    }

    pub fn parse<S, L>(&mut self, esil: S) -> Option<Token>
    where S: AsRef<str>, L: Tokenize<Token=Token> {
        // Mechanism:
        // The parser takes in a string to parse. Parser uses the lexer to break
        // up the string into tokens. At this time, it sets esil to be,
        // Some(Vec<Tokens>).
        // After the last token has been used up, the vector is empty, when
        // a request is made to parse again, esil is set to None and None is returned to indicate
        // end of parse for the string.

        if self.tokens.is_none() {
            self.tokens = Some(L::tokenize(esil));
        }

        while let Some(token) = self.tokens.as_mut().unwrap().pop_front() {
            match token {
                // Esil Internal Vars
                Token::IZero(_)
                | Token::ICarry(_)
                | Token::IParity(_)
                | Token::IOverflow(_)
                | Token::ISign(_) 
                | Token::IBorrow(_)
                | Token::ISize(_)
                | Token::IAddress(_) => {
                    let mut internal_q = self.evaluate_internal(&token);
                    while let Some(i) = internal_q.pop_back() {
                        self.tokens.as_mut().map(|v| v.push_front(i));
                    }
                },
                // Esil Operands
                Token::EConstant(_)
                | Token::EIdentifier(_) => {
                    self.stack.push(token);
                },
                // Parser Instructions.
                Token::PCopy(ref n) => {
                    // Copy 'n' elements from esil stack onto tstack
                    // _maintaining_ the order.
                    let len = self.stack.len();
                    if *n > len {
                        panic!("Request to `PCopy` too many elements!");
                    }
                    self.tstack.extend((&self.stack[len-n..]).iter().cloned());
                },
                Token::PPop(ref n) => { 
                    // Pop 'n' elements from esil stack onto tstack
                    // _maintaining_ the order.
                    let len = self.stack.len();
                    if *n > len {
                        panic!("Request to `PPop` too many elements!");
                    }
                    self.tstack.extend((&self.stack[len-n..]).iter().cloned());
                    self.stack.truncate(len - n);
                },
                // Not in use _yet_.
                Token::PSync => unimplemented!(),
                // Invalid. Let the Evaluator decide what to do with it.
                // Esil Opcodes. Return to the Evaluator.
                _ => {
                    return Some(token);
                },
            }
        }
        // This means that the parser is empty and there are no more tokens
        // to be processed. So we set tokens to None and return None.
        self.tokens = None;
        None
    }

    fn evaluate_internal(&self, t: &Token) -> VecDeque<Token> {
		match *t {
			Token::IZero(_) => { },
			Token::ICarry(_) => { },
			Token::IParity(_) => { },
			Token::IOverflow(_) => { },
			Token::ISign(_) => { }, 
			Token::IBorrow(_) => { },
			Token::ISize(_) => { },
			_ => unreachable!(),
		}
		VecDeque::new()
    }

    fn pop_op(&mut self) -> Option<Token> {
		if self.tstack.len() > 0 {
			self.tstack.pop()
		} else if self.stack.len() > 0 {
			self.stack.pop()
		} else {
			panic!("Insufficient operands!");
		}
    }

    // TODO: Think about changing this to a result type rather than option.
    pub fn fetch_operands(&mut self, t: &Token) -> (Option<Token>, Option<Token>) {
        // Match the operation.
        match *t {
            // Binary.
            Token::ECmp
            | Token::ELt
            | Token::EGt
            | Token::EEq
            | Token::ELsl
            | Token::ELsr
            | Token::ERor
            | Token::ERol
            | Token::EAnd
            | Token::EOr
            | Token::EMul
            | Token::EXor
            | Token::EAdd
            | Token::ESub
            | Token::EDiv
            | Token::EMod
            | Token::EPoke(_)
            | Token::EPeek(_) => { 
                (self.pop_op(), self.pop_op())
            },
            // Unary.
            Token::EPop
            | Token::ENeg
            | Token::EIf => { 
                (self.pop_op(), None)
            },
            // Zero operands
            Token::EDump => { (None, None) },
            Token::ENop => { (None, None) },
            // Unimplemented.
            Token::ETodo
            | Token::EInterrupt
            | Token::EGoto
            | Token::EBreak
            | Token::EClear
            | Token::EDup
            | Token::ETrap => {
                unimplemented!();
            },
            // Invalid
            _ => panic!("Invalid esil opcode!"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::lexer::*;

    struct Evaluator;
    impl ActionHandler for Evaluator {
        type InType = Token;
        type OutType = u8;
        fn init() -> Evaluator { Evaluator }
        fn evaluate(&mut self, i: &Self::InType) { println!("{:?}", i); }
        fn results(&mut self) -> Option<Self::OutType> { None }
    }

    #[test]
    fn parser_dummy() {
        let mut p = Parser::<Evaluator>::init();
        p.parse::<_, Tokenizer>("a,b,+=");
    }
}
