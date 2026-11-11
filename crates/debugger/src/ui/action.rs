use std::string::String;

type Command = String;
type Args = Option<String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    #[allow(unused)]
    Suspend,
    Resume,
    Quit,
    #[allow(unused)]
    Refresh,
    Error(String),
    #[allow(unused)]
    Help,
    FocusNext,
    FocusPrev,
    Focus,
    UnFocus,
    Up,
    Down,
    #[allow(unused)]
    Submit,
    Update,
    Tab(u32),
    TabNext,
    TabPrev,
    Go,
    Back,
    ToggleFullScreen,
    StatusLine(String),
    TimedStatusLine(String, u64),
    FocusFooter(Command, Args),
    FooterResult(Command, Args),
    Noop,
    ClosePopup,
    ShowDebug,
    Continue,
    Delete,
    Reload,
}
