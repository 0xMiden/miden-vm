use crossterm::event::{KeyEvent, MouseEvent};
use miden_assembly_syntax::diagnostics::Report;
use ratatui::layout::Rect;
use tokio::sync::mpsc::UnboundedSender;

use crate::ui::{
    action::Action,
    state::State,
    tui::{Event, EventResponse, Frame},
};

pub mod home;

pub trait Page {
    fn register_action_handler(&mut self, _tx: UnboundedSender<Action>) -> Result<(), Report> {
        Ok(())
    }

    fn init(&mut self, _state: &State) -> Result<(), Report> {
        Ok(())
    }

    fn focus(&mut self) -> Result<(), Report> {
        Ok(())
    }

    #[allow(unused)]
    fn unfocus(&mut self) -> Result<(), Report> {
        Ok(())
    }

    fn handle_events(
        &mut self,
        event: Event,
        state: &mut State,
    ) -> Result<Option<EventResponse<Action>>, Report> {
        let r = match event {
            Event::Key(key_event) => self.handle_key_events(key_event, state)?,
            Event::Mouse(mouse_event) => self.handle_mouse_events(mouse_event, state)?,
            _ => None,
        };
        Ok(r)
    }

    fn handle_key_events(
        &mut self,
        _key: KeyEvent,
        _state: &mut State,
    ) -> Result<Option<EventResponse<Action>>, Report> {
        Ok(None)
    }

    fn handle_mouse_events(
        &mut self,
        _mouse: MouseEvent,
        _state: &mut State,
    ) -> Result<Option<EventResponse<Action>>, Report> {
        Ok(None)
    }

    fn update(&mut self, _action: Action, _state: &mut State) -> Result<Option<Action>, Report> {
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect, state: &State) -> Result<(), Report>;
}
