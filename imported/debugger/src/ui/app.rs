use std::{boxed::Box, collections::HashMap, vec::Vec};

use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report};
use ratatui::{
    crossterm::event::KeyEvent,
    layout::{Constraint, Layout},
    prelude::Rect,
};
use tokio::sync::mpsc;

use super::{
    Action,
    pages::{Page, home::Home},
    panes::{Pane, debug::DebugPane, error::ErrorPane, footer::FooterPane, header::HeaderPane},
    state::{InputMode, State},
    tui,
};
use crate::config::DebuggerConfig;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Mode {
    #[default]
    Home,
}

pub struct App {
    pub pages: Vec<Box<dyn Page>>,
    pub keybindings: KeyBindings,
    pub active_page: usize,
    pub footer: FooterPane,
    pub header: HeaderPane,
    pub popup: Option<Box<dyn Pane>>,
    pub last_tick_key_events: Vec<KeyEvent>,
    pub mode: Mode,
    pub state: State,
    pub should_quit: bool,
    pub should_suspend: bool,
}

pub type KeyBindings = HashMap<Mode, HashMap<Vec<KeyEvent>, Action>>;

impl App {
    #[allow(dead_code)]
    pub async fn new(config: Box<DebuggerConfig>) -> Result<Self, Report> {
        let state = State::new(config)?;
        Self::from_state(state).await
    }

    /// Create an [App] from a pre-built [State].
    ///
    /// This is used for transaction debugging where the state is constructed
    /// externally with pre-recorded event replay data.
    pub async fn from_state(state: State) -> Result<Self, Report> {
        let home = Home::new()?;
        Ok(Self {
            pages: vec![Box::new(home)],
            keybindings: Default::default(),
            active_page: 0,
            footer: FooterPane::new(),
            header: HeaderPane::new(),
            popup: None,
            last_tick_key_events: vec![],
            mode: Mode::Home,
            state,
            should_quit: false,
            should_suspend: false,
        })
    }

    pub async fn run(&mut self) -> Result<(), Report> {
        let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

        let mut tui = tui::Tui::new()?
            .tick_rate(4.0) // 4 ticks per second
            .frame_rate(30.0); // 30 frames per second

        // Starts event handler, enters raw mode, enters alternate screen
        tui.enter()?;

        for page in self.pages.iter_mut() {
            page.register_action_handler(action_tx.clone())?;
        }

        for page in self.pages.iter_mut() {
            page.init(&self.state)?;
            page.focus()?;
        }

        self.header.init(&self.state)?;
        self.footer.init(&self.state)?;

        loop {
            if let Some(evt) = tui.next().await {
                let mut stop_event_propagation = self
                    .popup
                    .as_mut()
                    .and_then(|pane| pane.handle_events(evt.clone(), &mut self.state).ok())
                    .map(|response| match response {
                        Some(tui::EventResponse::Continue(action)) => {
                            action_tx.send(action).ok();
                            false
                        }
                        Some(tui::EventResponse::Stop(action)) => {
                            action_tx.send(action).ok();
                            true
                        }
                        _ => false,
                    })
                    .unwrap_or(false);
                stop_event_propagation = stop_event_propagation
                    || self
                        .pages
                        .get_mut(self.active_page)
                        .and_then(|page| page.handle_events(evt.clone(), &mut self.state).ok())
                        .map(|response| match response {
                            Some(tui::EventResponse::Continue(action)) => {
                                action_tx.send(action).ok();
                                false
                            }
                            Some(tui::EventResponse::Stop(action)) => {
                                action_tx.send(action).ok();
                                true
                            }
                            _ => false,
                        })
                        .unwrap_or(false);
                stop_event_propagation = stop_event_propagation
                    || self
                        .footer
                        .handle_events(evt.clone(), &mut self.state)
                        .map(|response| match response {
                            Some(tui::EventResponse::Continue(action)) => {
                                action_tx.send(action).ok();
                                false
                            }
                            Some(tui::EventResponse::Stop(action)) => {
                                action_tx.send(action).ok();
                                true
                            }
                            _ => false,
                        })
                        .unwrap_or(false);

                if !stop_event_propagation {
                    match evt {
                        tui::Event::Quit if self.state.input_mode == InputMode::Normal => {
                            action_tx.send(Action::Quit).into_diagnostic()?
                        }
                        tui::Event::Tick => action_tx.send(Action::Tick).into_diagnostic()?,
                        tui::Event::Render => action_tx.send(Action::Render).into_diagnostic()?,
                        tui::Event::Resize(x, y) => {
                            action_tx.send(Action::Resize(x, y)).into_diagnostic()?
                        }
                        tui::Event::Key(key) => {
                            if let Some(keymap) = self.keybindings.get(&self.mode) {
                                if let Some(action) = keymap.get(&vec![key]) {
                                    action_tx.send(action.clone()).into_diagnostic()?;
                                } else {
                                    // If the key was not handled as a single key action,
                                    // then consider it for multi-key combinations.
                                    self.last_tick_key_events.push(key);

                                    if let Some(action) = keymap.get(&self.last_tick_key_events) {
                                        action_tx.send(action.clone()).into_diagnostic()?;
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }

            while let Ok(action) = action_rx.try_recv() {
                if action != Action::Tick && action != Action::Render {
                    log::debug!("{action:?}");
                }
                match action {
                    Action::Tick => {
                        self.last_tick_key_events.clear();
                    }
                    Action::Quit if self.state.input_mode == InputMode::Normal => {
                        self.should_quit = true
                    }
                    Action::Suspend => self.should_suspend = true,
                    Action::Resume => self.should_suspend = false,
                    Action::Resize(w, h) => {
                        tui.resize(Rect::new(0, 0, w, h)).into_diagnostic()?;
                        tui.draw(|f| {
                            self.draw(f).unwrap_or_else(|err| {
                                action_tx
                                    .send(Action::Error(format!("Failed to draw: {err:?}")))
                                    .unwrap();
                            })
                        })
                        .into_diagnostic()?;
                    }
                    Action::Render => {
                        tui.draw(|f| {
                            self.draw(f).unwrap_or_else(|err| {
                                action_tx
                                    .send(Action::Error(format!("Failed to draw {err:?}")))
                                    .unwrap()
                            })
                        })
                        .into_diagnostic()?;
                    }
                    Action::ShowDebug => {
                        let debug_popup = DebugPane::default();
                        self.popup = Some(Box::new(debug_popup));
                    }
                    Action::Error(ref message) => {
                        self.popup = Some(Box::new(ErrorPane::new(message.clone())));
                    }
                    Action::ClosePopup => {
                        let _ = self.popup.take();
                    }
                    _ => (),
                }

                if let Some(popup) = self.popup.as_mut() {
                    if let Some(action) = popup.update(action.clone(), &mut self.state)? {
                        action_tx.send(action).into_diagnostic()?;
                    }
                } else if let Some(page) = self.pages.get_mut(self.active_page)
                    && let Some(action) = page.update(action.clone(), &mut self.state)?
                {
                    action_tx.send(action).into_diagnostic()?;
                }

                if let Some(action) = self.header.update(action.clone(), &mut self.state)? {
                    action_tx.send(action).into_diagnostic()?;
                }

                if let Some(action) = self.footer.update(action.clone(), &mut self.state)? {
                    action_tx.send(action).into_diagnostic()?;
                }
            }

            if self.should_suspend {
                tui.suspend()?;
                action_tx.send(Action::Resume).into_diagnostic()?;
                tui = tui::Tui::new()?;
                tui.enter()?;
            } else if self.should_quit {
                tui.stop()?;
                break;
            }
        }

        // stops event handler, exits raw mode, exits alternate screen
        tui.exit()?;

        Ok(())
    }

    fn draw(&mut self, frame: &mut tui::Frame<'_>) -> Result<(), Report> {
        let vertical_layout =
            Layout::vertical(vec![Constraint::Max(1), Constraint::Fill(1), Constraint::Max(1)])
                .split(frame.area());

        self.header.draw(frame, vertical_layout[0], &self.state)?;

        if let Some(page) = self.pages.get_mut(self.active_page) {
            page.draw(frame, vertical_layout[1], &self.state)?;
        }

        if let Some(popup) = self.popup.as_mut() {
            let popup_vertical_layout = Layout::vertical(vec![
                Constraint::Fill(1),
                popup.height_constraint(),
                Constraint::Fill(1),
            ])
            .split(frame.area());
            let popup_layout = Layout::horizontal(vec![
                Constraint::Fill(1),
                Constraint::Percentage(80),
                Constraint::Fill(1),
            ])
            .split(popup_vertical_layout[1]);
            popup.draw(frame, popup_layout[1], &self.state)?;
        }

        self.footer.draw(frame, vertical_layout[2], &self.state)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
