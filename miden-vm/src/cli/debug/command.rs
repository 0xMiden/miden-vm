use miden_processor::MemoryAddress;

/// debug commands supported by the debugger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugCommand {
    Continue,
    Next(usize),
    Rewind,
    Back(usize),
    PrintState,
    PrintStack,
    PrintStackItem(usize),
    PrintMem,
    PrintMemAddress(MemoryAddress),
    Clock,
    Quit,
    Help,
}

impl DebugCommand {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new DebugCommand created specified command string.
    ///
    /// # Errors
    /// Returns an error if the command cannot be parsed.
    pub fn parse(command: &str) -> Result<Option<Self>, String> {
        let mut tokens = command.split_whitespace();

        // fetch the identifier
        let identifier = match tokens.next() {
            Some(id) => id,
            None => return Ok(None),
        };

        // parse the appropriate command
        let command = match identifier {
            "n" | "next" => Self::parse_next(tokens.by_ref())?,
            "c" | "continue" => Self::Continue,
            "b" | "back" => Self::parse_back(tokens.by_ref())?,
            "r" | "rewind" => Self::Rewind,
            "p" | "print" => Self::parse_print(tokens.by_ref())?,
            "l" | "clock" => Self::Clock,
            "h" | "?" | "help" => Self::Help,
            "q" | "quit" => Self::Quit,
            _ => {
                return Err(format!(
                    "malformed command - does not match any known command: `{command}`"
                ));
            },
        };

        // command is fully parsed and shouldn't contain further tokens
        if let Some(t) = tokens.next() {
            return Err(format!("malformed command - unexpected token `{t}`"));
        }

        Ok(Some(command))
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// parse next command - next num_cycles
    fn parse_next<'a, I>(mut tokens: I) -> Result<Self, String>
    where
        I: Iterator<Item = &'a str>,
    {
        let num_cycles = match tokens.next() {
            Some(n) => n.parse::<usize>().map_err(|err| {
                format!("malformed `next` command - failed to parse number of cycles: `{n}` {err}")
            })?,
            None => return Ok(Self::Next(1)),
        };
        Ok(Self::Next(num_cycles))
    }

    /// parse back command - back num_cycles
    fn parse_back<'a, I>(mut tokens: I) -> Result<Self, String>
    where
        I: Iterator<Item = &'a str>,
    {
        let num_cycles = match tokens.next() {
            Some(n) => n.parse::<usize>().map_err(|err| {
                format!("malformed `back` command - failed to parse number of cycles: `{n}` {err}")
            })?,
            None => return Ok(Self::Back(1)),
        };
        Ok(Self::Back(num_cycles))
    }

    /// parse print command - `p [m|s] [addr]`
    fn parse_print<'a, I>(mut tokens: I) -> Result<Self, String>
    where
        I: Iterator<Item = &'a str>,
    {
        let command = match tokens.next() {
            Some(c) => c,
            None => return Ok(Self::PrintState),
        };

        // match the command variant
        let command = match command {
            "m" | "mem" => Self::PrintMem,
            "s" | "stack" => Self::PrintStack,
            _ => {
                return Err(format!(
                    "malformed `print` command - unexpected subcommand: `{command}`"
                ));
            },
        };

        // parse the subcommand argument, if present
        let argument =
            tokens.next().map(|t| t.parse::<u64>()).transpose().map_err(|err| {
                format!("malformed command - failed to parse print argument: {err}")
            })?;

        match (command, argument) {
            (Self::PrintMem, Some(arg)) => Ok(Self::PrintMemAddress(
                u32::try_from(arg).expect("memory address should not exceed 2^32").into(),
            )),
            (Self::PrintStack, Some(arg)) => Ok(Self::PrintStackItem(arg as usize)),
            (_, Some(_)) => unreachable!("the command was previously parsed within this block"),
            (_, None) => Ok(command),
        }
    }
}
