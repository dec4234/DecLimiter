use std::time::Duration;
use ratatui::crossterm::event;
use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind};
use ratatui::{Frame};
use ratatui::layout::{Constraint, Layout};
use ratatui::prelude::{Color, Line, Modifier, Style};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use declimiter_lib::limiter::ProcessPair;
use declimiter_lib::util::{find_process, parse_datarate, Datarate};
use crate::error::LimiterCLIError;

pub fn init_search() -> Result<Option<(ProcessPair, Datarate)>, LimiterCLIError> {
	let result = open_search()?;
	
	let speed = get_download_speed()?;

	Ok(result.map(|proc| (proc, speed)))
}

pub fn get_download_speed() -> Result<u64, LimiterCLIError> {
	let mut terminal = ratatui::init();

	let mut input = String::new();

	let result = loop {
		terminal.draw(|f| {
			let layout = Layout::vertical([Constraint::Length(3), Constraint::Length(3)]);
			let [input_area, help_area] = layout.areas(f.area());

			let block = Block::bordered().title(" Set Download Speed (bytes/sec) ");
			let paragraph = Paragraph::new(input.as_str())
				.block(block)
				.style(Style::default().fg(Color::Yellow));

			f.render_widget(paragraph, input_area);

			let help = Paragraph::new("Examples: 500k, 2m, 100000 | Enter=Confirm Esc=Cancel")
				.block(Block::bordered())
				.style(Style::default().fg(Color::DarkGray));

			f.render_widget(help, help_area);
		})?;

		if event::poll(Duration::from_millis(16))? {
			if let Event::Key(key) = event::read()? {
				if key.kind == KeyEventKind::Press {
					match key.code {
						KeyCode::Enter => {
							if let Ok(value) = parse_datarate(&input) {
								break Ok(value);
							}
						}
						KeyCode::Esc => break Err(LimiterCLIError::UserAbort),
						KeyCode::Char(c) => {
							if c.is_ascii_alphanumeric() {
								input.push(c);
							}
						}
						KeyCode::Backspace => {
							input.pop();
						}
						_ => {}
					}
				}
			}
		}
	};

	ratatui::restore();
	result
}


/// Opens a TUI for searching and selecting a process from the list of running processes.
///
/// Returns the user's selected process as an `Option<ProcessPair>`, where `ProcessPair` is a tuple of (PID, Process Name).
pub(crate) fn open_search() -> Result<Option<ProcessPair>, LimiterCLIError> {
	let mut terminal = ratatui::init();
	
	let mut query = String::new();
	let mut list_state = ListState::default();
	list_state.select(Some(0));

	let mut processes = find_process(&query);

	// Listen for any user input, add to the serach bar and update the query
	loop {
		terminal.draw(|f| ui(f, &query, &processes, &mut list_state))?;

		if event::poll(Duration::from_millis(16))? {
			if let Event::Key(key) = event::read()? {
				if key.kind == KeyEventKind::Press {
					match key.code {
						KeyCode::Up => list_state.select_previous(),
						KeyCode::Down => list_state.select_next(),

						KeyCode::Enter => {
							if let Some(index) = list_state.selected() {
								if let Some(selected) = processes.get(index) {
									ratatui::restore();
									return Ok(Some(selected.clone()));
								}
							}
						}
						KeyCode::Esc => {
							ratatui::restore();
							return Ok(None) 
						},

						KeyCode::Char(c) => {
							query.push(c);
							processes = find_process(&query);
							list_state.select(Some(0));
						}
						KeyCode::Backspace => {
							query.pop();
							processes = find_process(&query);
							list_state.select(Some(0));
						}
						_ => {}
					}
				}
			}
		}
	}
}

/// Given the current search query, list of processes, and list state, renders the TUI components to the terminal frame.
fn ui(frame: &mut Frame, query: &str, processes: &[ProcessPair], state: &mut ListState) {
	let layout = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]);
	let [search_area, list_area] = layout.areas(frame.area());

	let search_block = Block::bordered().title(" Search Process ");
	let input = Paragraph::new(query)
		.block(search_block)
		.style(Style::default().fg(Color::Yellow));

	frame.render_widget(input, search_area);

	let items: Vec<ListItem> = processes
		.iter()
		.map(|p| {
			let text = format!("{} [PID: {}]", p.1, p.0);
			ListItem::new(Line::from(text))
		})
		.collect();

	let list = List::new(items)
		.block(Block::bordered().title(" Results "))
		.highlight_style(Style::new().add_modifier(Modifier::REVERSED).fg(Color::Green))
		.highlight_symbol(">> ");

	frame.render_stateful_widget(list, list_area, state);
}