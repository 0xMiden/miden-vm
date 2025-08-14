#[derive(Debug, PartialEq, Clone)]
pub enum ConstructType {
    Proc,
    Export,
    Begin,
    End,
    While,
    Repeat,
    If,
    Else,
}

impl ConstructType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "proc" => Some(Self::Proc),
            "export" => Some(Self::Export),
            "begin" => Some(Self::Begin),
            "end" => Some(Self::End),
            "while" => Some(Self::While),
            "repeat" => Some(Self::Repeat),
            "if" => Some(Self::If),
            "else" => Some(Self::Else),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum LineType {
    Import(String),
    Comment(String),
    Empty,
    Other(String),
}
