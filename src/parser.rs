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
                    let mut internal_q = self.evaluate_internal(token);
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
                Token::PCopy(usize) => { },
                Token::PPop(usize) => { },
                Token::PSync => { },
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

    fn evaluate_internal(&self, t: Token) -> VecDeque<Token> {
        unimplemented!()
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
