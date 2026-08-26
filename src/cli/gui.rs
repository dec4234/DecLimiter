use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use declimiter_lib::limiter::{DecLimiter, LimitConfig, LimitsMap, ProcessTraffic};
use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::cli::icons::IconCache;
use crate::cli::publisher::PublisherCache;
use crate::config::{self, ProcessConfig, ProcessesConfig};

const SYSTEM_PID: u32 = 0;
const ROW_HEIGHT: f32 = 24.0;
const ICON_SIZE: f32 = 16.0;

/// Colors of the interface. The palette is a cool, high contrast dark theme in
/// the style of NetLimiter, with a blue accent and square corners.
mod theme {
	use eframe::egui::Color32;

	pub const BG_WINDOW: Color32 = Color32::from_rgb(0x1B, 0x1F, 0x24);
	pub const BG_HEADER: Color32 = Color32::from_rgb(0x23, 0x2A, 0x33);
	pub const BG_TABLE: Color32 = Color32::from_rgb(0x13, 0x17, 0x1B);
	pub const BG_STRIPE: Color32 = Color32::from_rgb(0x1A, 0x1F, 0x25);
	pub const BG_INPUT: Color32 = Color32::from_rgb(0x0F, 0x12, 0x16);

	pub const BORDER: Color32 = Color32::from_rgb(0x30, 0x39, 0x43);
	pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x44, 0x50, 0x5D);

	pub const TEXT: Color32 = Color32::from_rgb(0xD8, 0xDF, 0xE7);
	pub const TEXT_STRONG: Color32 = Color32::from_rgb(0xF2, 0xF5, 0xF8);
	pub const TEXT_WEAK: Color32 = Color32::from_rgb(0x87, 0x95, 0xA4);
	/// Placeholder text in the search field. Darker than TEXT_WEAK so that it
	/// does not read as a value that is already in the field.
	pub const HINT: Color32 = Color32::from_rgb(0x56, 0x60, 0x6C);

	pub const ACCENT: Color32 = Color32::from_rgb(0x1F, 0x6F, 0xEB);
	pub const ACCENT_LIGHT: Color32 = Color32::from_rgb(0x58, 0xA6, 0xFF);

	pub const DOWNLOAD: Color32 = Color32::from_rgb(0x4D, 0xA3, 0xFF);
	pub const UPLOAD: Color32 = Color32::from_rgb(0x4F, 0xD1, 0x8B);
	pub const BLOCKED: Color32 = Color32::from_rgb(0xE5, 0x53, 0x4B);
	pub const LIMITED: Color32 = Color32::from_rgb(0xE3, 0xA8, 0x21);
}

/// Launch the GUI network monitor window.
pub fn launch_gui() {
	simple_logger::init_with_level(log::Level::Debug).ok();

	let stats: Arc<Mutex<Vec<ProcessTraffic>>> = Arc::new(Mutex::new(Vec::new()));
	let system_totals: Arc<Mutex<ProcessTraffic>> = Arc::new(Mutex::new(ProcessTraffic {
		pid: 0,
		name: "System".to_string(),
		download_bytes: 0,
		upload_bytes: 0,
		download_speed: 0.0,
		upload_speed: 0.0,
	}));
	let monitor_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
	let limits: Arc<Mutex<Option<LimitsMap>>> = Arc::new(Mutex::new(None));

	let stats_bg = stats.clone();
	let totals_bg = system_totals.clone();
	let error_bg = monitor_error.clone();
	let limits_bg = limits.clone();
	thread::spawn(move || {
		let rt = tokio::runtime::Runtime::new().unwrap();
		rt.block_on(async {
			let limiter = match DecLimiter::new() {
				Ok(l) => l,
				Err(e) => {
					*error_bg.lock().unwrap() = Some(format!("Failed to initialize: {}\n\nMake sure:\n1. WinpkFilter driver is installed\n2. Running as Administrator", e));
					return;
				}
			};

			*limits_bg.lock().unwrap() = Some(limiter.limits());

			limiter.start();
			limiter.start_monitor();
			limiter.start_speed_calculator();

			loop {
				let snapshot = limiter.get_snapshot();
				let totals = limiter.get_totals();
				*stats_bg.lock().unwrap() = snapshot;
				*totals_bg.lock().unwrap() = totals;
				tokio::time::sleep(Duration::from_millis(500)).await;
			}
		});
	});

	let icon = {
		let icon_bytes = include_bytes!("../../assets/icon.png");
		let img = image::load_from_memory(icon_bytes).expect("Failed to load icon").into_rgba8();
		let (w, h) = img.dimensions();
		egui::IconData { rgba: img.into_raw(), width: w, height: h }
	};

	let options = eframe::NativeOptions {
		viewport: egui::ViewportBuilder::default().with_inner_size([980.0, 620.0]).with_title("DecLimiter").with_icon(Arc::new(icon)),
		..Default::default()
	};

	// Load saved process configs and app config from disk
	config::load_app_config();
	let group_states = load_group_states();

	eframe::run_native(
		"DecLimiter",
		options,
		Box::new(|cc| {
			configure_style(&cc.egui_ctx);
			Ok(Box::new(DecLimiterApp {
				stats,
				system_totals,
				monitor_error,
				limits_handle: limits,
				group_states,
				pid_states: HashMap::new(),
				expanded: HashSet::new(),
				sort_column: SortColumn::DownloadSpeed,
				sort_ascending: false,
				search_query: String::new(),
				selection: None,
				known_pids: HashMap::new(),
				frozen_order: None,
				icons: IconCache::new(),
				publishers: PublisherCache::new(),
			}))
		}),
	)
	.unwrap();
}

/// Applies the square cornered, blue accented theme.
fn configure_style(ctx: &egui::Context) {
	let mut visuals = egui::Visuals::dark();

	visuals.panel_fill = theme::BG_WINDOW;
	visuals.window_fill = theme::BG_WINDOW;
	visuals.extreme_bg_color = theme::BG_INPUT;
	visuals.faint_bg_color = theme::BG_STRIPE;
	visuals.override_text_color = Some(theme::TEXT);

	visuals.window_rounding = egui::Rounding::ZERO;
	visuals.menu_rounding = egui::Rounding::ZERO;
	visuals.window_stroke = egui::Stroke::new(1.0, theme::BORDER);
	visuals.window_shadow = egui::epaint::Shadow::NONE;
	visuals.popup_shadow = egui::epaint::Shadow::NONE;

	visuals.selection.bg_fill = theme::ACCENT;
	visuals.selection.stroke = egui::Stroke::new(1.0, theme::TEXT_STRONG);

	visuals.widgets.noninteractive.bg_fill = theme::BG_WINDOW;
	visuals.widgets.noninteractive.weak_bg_fill = theme::BG_WINDOW;
	visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, theme::BORDER);
	visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, theme::TEXT);

	visuals.widgets.inactive.bg_fill = theme::BG_HEADER;
	visuals.widgets.inactive.weak_bg_fill = theme::BG_HEADER;
	visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, theme::BORDER);
	visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, theme::TEXT);

	visuals.widgets.hovered.bg_fill = theme::BG_HEADER;
	visuals.widgets.hovered.weak_bg_fill = theme::BG_HEADER;
	visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, theme::BORDER_STRONG);
	visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, theme::TEXT_STRONG);

	visuals.widgets.active.bg_fill = theme::ACCENT;
	visuals.widgets.active.weak_bg_fill = theme::ACCENT;
	visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, theme::ACCENT_LIGHT);
	visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, theme::TEXT_STRONG);

	visuals.widgets.open.bg_fill = theme::BG_HEADER;
	visuals.widgets.open.weak_bg_fill = theme::BG_HEADER;
	visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, theme::BORDER_STRONG);
	visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, theme::TEXT);

	// Square corners on every widget class.
	for widget in [&mut visuals.widgets.noninteractive, &mut visuals.widgets.inactive, &mut visuals.widgets.hovered, &mut visuals.widgets.active, &mut visuals.widgets.open] {
		widget.rounding = egui::Rounding::ZERO;
		widget.expansion = 0.0;
	}

	ctx.set_visuals(visuals);

	let mut style = (*ctx.style()).clone();
	style.spacing.item_spacing = egui::vec2(6.0, 4.0);
	style.spacing.button_padding = egui::vec2(8.0, 3.0);
	style.spacing.menu_margin = egui::Margin::same(4.0);
	style.spacing.scroll.floating = false;
	style.spacing.scroll.bar_width = 10.0;
	ctx.set_style(style);
}

/// Reads the saved per process settings from disk into limit states.
fn load_group_states() -> HashMap<String, ProcessLimitState> {
	config::load_processes_config().iter().map(|(name, cfg)| (name.clone(), ProcessLimitState::from_process_config(cfg))).collect()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum SortColumn {
	Name,
	Pid,
	DownloadSpeed,
	UploadSpeed,
}

/// What the detail panel on the right shows.
#[derive(Clone, PartialEq)]
enum Selection {
	/// All traffic, regardless of process.
	System,
	/// Every instance of one application, keyed by process name.
	Group(String),
	/// One single process instance.
	Process(u32),
}

/// One application, together with all of its running instances.
struct AppGroup {
	name: String,
	procs: Vec<ProcessTraffic>,
	download_speed: f64,
	upload_speed: f64,
	download_bytes: u64,
	upload_bytes: u64,
}

/// The row order of one frame, kept so that the table can hold that order
/// while the user keeps the Ctrl key down. Windows Task Manager does the same.
struct FrozenOrder {
	/// Application names, in the order they were shown when the key went down.
	groups: Vec<String>,
	/// For each application name, the PIDs in the order they were shown.
	procs: HashMap<String, Vec<u32>>,
}

impl FrozenOrder {
	/// Records the order of the groups as they are now.
	fn capture(groups: &[AppGroup]) -> Self {
		FrozenOrder {
			groups: groups.iter().map(|g| g.name.clone()).collect(),
			procs: groups.iter().map(|g| (g.name.clone(), g.procs.iter().map(|p| p.pid).collect())).collect(),
		}
	}

	/// Puts the groups back into the recorded order. Applications and
	/// processes that started after the freeze keep their sorted order and go
	/// to the end, so that the recorded lines never move.
	fn apply(&self, groups: &mut [AppGroup]) {
		let rank: HashMap<&str, usize> = self.groups.iter().enumerate().map(|(i, name)| (name.as_str(), i)).collect();
		groups.sort_by_key(|g| rank.get(g.name.as_str()).copied().unwrap_or(usize::MAX));

		for group in groups.iter_mut() {
			let Some(pids) = self.procs.get(&group.name) else {
				continue;
			};
			let pid_rank: HashMap<u32, usize> = pids.iter().enumerate().map(|(i, pid)| (*pid, i)).collect();
			group.procs.sort_by_key(|p| pid_rank.get(&p.pid).copied().unwrap_or(usize::MAX));
		}
	}
}

/// A line of the table. Child lines only appear while their group is expanded.
enum VisibleRow {
	System,
	Group(usize),
	Child(usize, usize),
}

#[derive(Clone, Copy, PartialEq)]
enum SpeedUnit {
	Bps,
	KBps,
	MBps,
	GBps,
}

impl SpeedUnit {
	const ALL: [SpeedUnit; 4] = [SpeedUnit::Bps, SpeedUnit::KBps, SpeedUnit::MBps, SpeedUnit::GBps];

	fn label(&self) -> &'static str {
		match self {
			Self::Bps => "B/s",
			Self::KBps => "KB/s",
			Self::MBps => "MB/s",
			Self::GBps => "GB/s",
		}
	}

	fn multiplier(&self) -> f64 {
		match self {
			Self::Bps => 1.0,
			Self::KBps => 1_024.0,
			Self::MBps => 1_048_576.0,
			Self::GBps => 1_073_741_824.0,
		}
	}

	fn as_str(&self) -> &'static str {
		match self {
			Self::Bps => "Bps",
			Self::KBps => "KBps",
			Self::MBps => "MBps",
			Self::GBps => "GBps",
		}
	}

	fn from_str(s: &str) -> Self {
		match s {
			"Bps" => Self::Bps,
			"KBps" => Self::KBps,
			"MBps" => Self::MBps,
			"GBps" => Self::GBps,
			_ => Self::KBps,
		}
	}
}

#[derive(Clone, PartialEq)]
struct ProcessLimitState {
	dl_enabled: bool,
	dl_value: f64,
	dl_unit: SpeedUnit,
	dl_blocked: bool,
	ul_enabled: bool,
	ul_value: f64,
	ul_unit: SpeedUnit,
	ul_blocked: bool,
}

impl Default for ProcessLimitState {
	fn default() -> Self {
		Self {
			dl_enabled: false,
			dl_value: 0.0,
			dl_unit: SpeedUnit::KBps,
			dl_blocked: false,
			ul_enabled: false,
			ul_value: 0.0,
			ul_unit: SpeedUnit::KBps,
			ul_blocked: false,
		}
	}
}

impl ProcessLimitState {
	fn download_byterate(&self) -> Option<u64> {
		if self.dl_blocked {
			Some(0)
		} else if self.dl_enabled && self.dl_value > 0.0 {
			Some((self.dl_value * self.dl_unit.multiplier()) as u64)
		} else {
			None
		}
	}

	fn upload_byterate(&self) -> Option<u64> {
		if self.ul_blocked {
			Some(0)
		} else if self.ul_enabled && self.ul_value > 0.0 {
			Some((self.ul_value * self.ul_unit.multiplier()) as u64)
		} else {
			None
		}
	}

	fn dl_active(&self) -> bool {
		self.dl_blocked || (self.dl_enabled && self.dl_value > 0.0)
	}

	fn ul_active(&self) -> bool {
		self.ul_blocked || (self.ul_enabled && self.ul_value > 0.0)
	}

	fn to_process_config(&self) -> ProcessConfig {
		ProcessConfig {
			dl_enabled: self.dl_enabled,
			dl_value: self.dl_value,
			dl_unit: self.dl_unit.as_str().to_string(),
			dl_blocked: self.dl_blocked,
			ul_enabled: self.ul_enabled,
			ul_value: self.ul_value,
			ul_unit: self.ul_unit.as_str().to_string(),
			ul_blocked: self.ul_blocked,
		}
	}

	fn from_process_config(cfg: &ProcessConfig) -> Self {
		Self {
			dl_enabled: cfg.dl_enabled,
			dl_value: cfg.dl_value,
			dl_unit: SpeedUnit::from_str(&cfg.dl_unit),
			dl_blocked: cfg.dl_blocked,
			ul_enabled: cfg.ul_enabled,
			ul_value: cfg.ul_value,
			ul_unit: SpeedUnit::from_str(&cfg.ul_unit),
			ul_blocked: cfg.ul_blocked,
		}
	}

	fn has_any_setting(&self) -> bool {
		self.dl_enabled || self.dl_blocked || self.dl_value > 0.0 || self.ul_enabled || self.ul_blocked || self.ul_value > 0.0
	}
}

/// The limit markers shown at the end of a row.
#[derive(Clone, Copy, Default)]
struct LimitFlags {
	dl_active: bool,
	ul_active: bool,
	dl_blocked: bool,
	ul_blocked: bool,
}

impl LimitFlags {
	fn of(state: &ProcessLimitState) -> Self {
		Self {
			dl_active: state.dl_active(),
			ul_active: state.ul_active(),
			dl_blocked: state.dl_blocked,
			ul_blocked: state.ul_blocked,
		}
	}

	fn merge(self, other: Self) -> Self {
		Self {
			dl_active: self.dl_active || other.dl_active,
			ul_active: self.ul_active || other.ul_active,
			dl_blocked: self.dl_blocked || other.dl_blocked,
			ul_blocked: self.ul_blocked || other.ul_blocked,
		}
	}
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

struct DecLimiterApp {
	stats: Arc<Mutex<Vec<ProcessTraffic>>>,
	system_totals: Arc<Mutex<ProcessTraffic>>,
	monitor_error: Arc<Mutex<Option<String>>>,
	limits_handle: Arc<Mutex<Option<LimitsMap>>>,
	/// Limits that apply to every instance of an application. These persist.
	group_states: HashMap<String, ProcessLimitState>,
	/// Limits set on one single instance. These override the group limit and
	/// are not written to disk.
	pid_states: HashMap<u32, ProcessLimitState>,
	/// Names of the groups whose instance list is open.
	expanded: HashSet<String>,
	sort_column: SortColumn,
	sort_ascending: bool,
	search_query: String,
	selection: Option<Selection>,
	/// Maps every PID we have seen to its process name.
	known_pids: HashMap<u32, String>,
	/// The row order that is held while the user keeps the Ctrl key down. It
	/// is `None` when the table sorts freely.
	frozen_order: Option<FrozenOrder>,
	icons: IconCache,
	/// Publisher of each application, read from its executable.
	publishers: PublisherCache,
}

impl DecLimiterApp {
	/// Collects the running processes into one group per application name.
	fn build_groups(&self, stats: Vec<ProcessTraffic>) -> Vec<AppGroup> {
		let mut index: HashMap<String, usize> = HashMap::new();
		let mut groups: Vec<AppGroup> = Vec::new();

		for proc in stats {
			let idx = match index.get(&proc.name) {
				Some(&i) => i,
				None => {
					groups.push(AppGroup {
						name: proc.name.clone(),
						procs: Vec::new(),
						download_speed: 0.0,
						upload_speed: 0.0,
						download_bytes: 0,
						upload_bytes: 0,
					});
					index.insert(proc.name.clone(), groups.len() - 1);
					groups.len() - 1
				}
			};

			let group = &mut groups[idx];
			group.download_speed += proc.download_speed;
			group.upload_speed += proc.upload_speed;
			group.download_bytes += proc.download_bytes;
			group.upload_bytes += proc.upload_bytes;
			group.procs.push(proc);
		}

		groups
	}

	fn sort_groups(&self, groups: &mut Vec<AppGroup>) {
		let ascending = self.sort_ascending;
		let column = self.sort_column;

		groups.sort_by(|a, b| {
			let ord = match column {
				SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
				SortColumn::Pid => a.procs.len().cmp(&b.procs.len()),
				SortColumn::DownloadSpeed => compare_f64(a.download_speed, b.download_speed),
				SortColumn::UploadSpeed => compare_f64(a.upload_speed, b.upload_speed),
			};
			if ascending { ord } else { ord.reverse() }
		});

		for group in groups.iter_mut() {
			group.procs.sort_by(|a, b| {
				let ord = match column {
					SortColumn::Name | SortColumn::Pid => a.pid.cmp(&b.pid),
					SortColumn::DownloadSpeed => compare_f64(a.download_speed, b.download_speed),
					SortColumn::UploadSpeed => compare_f64(a.upload_speed, b.upload_speed),
				};
				if ascending { ord } else { ord.reverse() }
			});
		}
	}

	/// Returns the limit that is in force for one PID: the instance override if
	/// there is one, otherwise the limit of its application group.
	fn effective_state(&self, pid: u32, name: &str) -> Option<&ProcessLimitState> {
		self.pid_states.get(&pid).or_else(|| self.group_states.get(name))
	}

	fn flags_for_pid(&self, pid: u32, name: &str) -> LimitFlags {
		self.effective_state(pid, name).map(LimitFlags::of).unwrap_or_default()
	}

	fn flags_for_group(&self, group: &AppGroup) -> LimitFlags {
		group.procs.iter().fold(LimitFlags::default(), |acc, p| acc.merge(self.flags_for_pid(p.pid, &group.name)))
	}

	/// Pushes the current limit states down to the packet limiter.
	fn apply_limits(&self) {
		let handle_lock = self.limits_handle.lock().unwrap();
		let Some(limits) = handle_lock.as_ref() else { return };
		let mut limits_lock = limits.write().unwrap();
		limits_lock.clear();

		let mut effective: HashMap<u32, &ProcessLimitState> = HashMap::new();
		for (&pid, name) in &self.known_pids {
			if let Some(state) = self.group_states.get(name) {
				effective.insert(pid, state);
			}
		}
		for (&pid, state) in &self.pid_states {
			effective.insert(pid, state);
		}

		for (pid, state) in effective {
			let dl = state.download_byterate();
			let ul = state.upload_byterate();
			if dl.is_some() || ul.is_some() {
				limits_lock.insert(pid, LimitConfig { download_byterate: dl, upload_byterate: ul });
			}
		}
	}

	/// Writes the per application limits to disk.
	fn save_to_disk(&self) {
		let mut config = ProcessesConfig::new();
		for (name, state) in &self.group_states {
			if state.has_any_setting() {
				config.insert(name.clone(), state.to_process_config());
			}
		}
		config::save_processes_config(&config);
	}
}

impl eframe::App for DecLimiterApp {
	fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
		ctx.request_repaint_after(Duration::from_millis(500));

		// Check for monitor errors
		if let Some(err) = self.monitor_error.lock().unwrap().as_ref() {
			egui::CentralPanel::default().show(ctx, |ui| {
				ui.vertical_centered(|ui| {
					ui.add_space(100.0);
					ui.heading(egui::RichText::new("Monitor Error").color(theme::BLOCKED).size(24.0));
					ui.add_space(20.0);
					ui.label(egui::RichText::new(err).size(16.0));
				});
			});
			return;
		}

		let mut stats = self.stats.lock().unwrap().clone();

		// Keep the PID to name map current so limits follow new instances.
		let mut new_pids = false;
		for proc in &stats {
			if proc.pid != SYSTEM_PID && !self.known_pids.contains_key(&proc.pid) {
				self.known_pids.insert(proc.pid, proc.name.clone());
				new_pids = self.group_states.contains_key(&proc.name) || new_pids;
			}
		}
		if new_pids {
			self.apply_limits();
		}

		// Filter by search query. The query matches the name, the PID, or the
		// publisher that the executable declares.
		if !self.search_query.is_empty() {
			let query = self.search_query.to_lowercase();
			let mut kept: Vec<ProcessTraffic> = Vec::with_capacity(stats.len());
			for proc in stats {
				let publisher = self.publishers.get(&proc.name, proc.pid).unwrap_or_default();
				if proc.name.to_lowercase().contains(&query) || proc.pid.to_string().contains(&query) || publisher.to_lowercase().contains(&query) {
					kept.push(proc);
				}
			}
			stats = kept;
		}

		let system_row = self.system_totals.lock().unwrap().clone();
		let mut groups = self.build_groups(stats);
		self.sort_groups(&mut groups);

		// Hold the row order while the Ctrl key is down. The speeds keep
		// updating, but no line moves, so that a row is easy to click.
		let freeze_held = ctx.input(|i| i.modifiers.ctrl);
		if freeze_held {
			match &self.frozen_order {
				Some(order) => order.apply(&mut groups),
				None => self.frozen_order = Some(FrozenOrder::capture(&groups)),
			}
		} else {
			self.frozen_order = None;
		}

		let instance_count: usize = groups.iter().map(|g| g.procs.len()).sum();

		// Flatten the groups into the lines the table draws.
		let mut visible: Vec<VisibleRow> = vec![VisibleRow::System];
		for (gi, group) in groups.iter().enumerate() {
			visible.push(VisibleRow::Group(gi));
			if group.procs.len() > 1 && self.expanded.contains(&group.name) {
				for ci in 0..group.procs.len() {
					visible.push(VisibleRow::Child(gi, ci));
				}
			}
		}

		let mut clicked_column: Option<SortColumn> = None;
		let mut new_selection = self.selection.clone();
		let mut toggle_group: Option<String> = None;

		// -- Top panel --
		egui::TopBottomPanel::top("header").frame(egui::Frame::none().fill(theme::BG_HEADER).inner_margin(egui::Margin::symmetric(10.0, 6.0))).show(ctx, |ui| {
			ui.horizontal(|ui| {
				ui.label(egui::RichText::new("DecLimiter").strong().size(16.0).color(theme::TEXT_STRONG));
				ui.add_space(4.0);
				ui.label(egui::RichText::new("Network Monitor").color(theme::TEXT_WEAK));

				ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
					ui.label(egui::RichText::new(format!("{} apps / {} processes", groups.len(), instance_count)).color(theme::TEXT_WEAK));
					if freeze_held {
						ui.add_space(10.0);
						ui.label(egui::RichText::new("Order held (Ctrl)").color(theme::LIMITED));
					}
				});
			});
			ui.add_space(6.0);
			ui.horizontal(|ui| {
				ui.label(egui::RichText::new("Search").color(theme::TEXT_WEAK));
				let search = ui.add(
					egui::TextEdit::singleline(&mut self.search_query)
						.desired_width(300.0)
						.font(egui::FontId::proportional(14.0))
						.margin(egui::Margin { left: 6.0, right: 26.0, top: 5.0, bottom: 5.0 })
						.hint_text(egui::RichText::new("Name, PID, or publisher").color(theme::HINT)),
				);
				// The clear control sits inside the field, as in most search boxes.
				if !self.search_query.is_empty() {
					let rect = egui::Rect::from_min_size(egui::pos2(search.rect.right() - 22.0, search.rect.top()), egui::vec2(20.0, search.rect.height()));
					if draw_clear_button(ui, rect).clicked() {
						self.search_query.clear();
					}
				}
				ui.separator();
				if ui.button("Expand all").clicked() {
					for group in &groups {
						if group.procs.len() > 1 {
							self.expanded.insert(group.name.clone());
						}
					}
				}
				if ui.button("Collapse all").clicked() {
					self.expanded.clear();
				}
			});
		});

		// -- Bottom status bar --
		egui::TopBottomPanel::bottom("status").frame(egui::Frame::none().fill(theme::BG_HEADER).inner_margin(egui::Margin::symmetric(10.0, 5.0))).show(ctx, |ui| {
			ui.horizontal(|ui| {
				ui.label(egui::RichText::new("Total").color(theme::TEXT_WEAK));
				ui.separator();
				ui.label(egui::RichText::new("DL").strong().color(theme::DOWNLOAD));
				ui.label(egui::RichText::new(format_speed(system_row.download_speed)).color(theme::TEXT));
				ui.separator();
				ui.label(egui::RichText::new("UL").strong().color(theme::UPLOAD));
				ui.label(egui::RichText::new(format_speed(system_row.upload_speed)).color(theme::TEXT));

				ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
					let active = self.group_states.values().filter(|s| s.has_any_setting()).count() + self.pid_states.values().filter(|s| s.has_any_setting()).count();
					ui.label(egui::RichText::new(format!("{active} rules active")).color(theme::TEXT_WEAK));
				});
			});
		});

		// -- Right detail panel --
		let mut limits_changed = false;
		let mut save_needed = false;
		{
			let selection = self.selection.clone();
			egui::SidePanel::right("details").frame(egui::Frame::none().fill(theme::BG_WINDOW).inner_margin(egui::Margin::same(10.0))).resizable(false).exact_width(320.0).show(ctx, |ui| {
				ui.set_width(ui.available_width());

				// The close control sits in the corner of the panel and
				// does not take a line of its own.
				if selection.is_some() {
					let rect = egui::Rect::from_min_size(egui::pos2(ui.max_rect().right() - 20.0, ui.max_rect().top()), egui::vec2(20.0, 20.0));
					if draw_close_button(ui, rect).clicked() {
						new_selection = None;
					}
				}

				let Some(selection) = selection else {
					detail_placeholder(ui);
					return;
				};
				match &selection {
					Selection::System => {
						let mut state = self.pid_states.get(&SYSTEM_PID).cloned().unwrap_or_default();
						let before = state.clone();
						detail_header(ui, "All Traffic", "Every process on this machine", &system_row);
						limit_editor(ui, "system", &mut state);
						if state != before {
							self.pid_states.insert(SYSTEM_PID, state);
							limits_changed = true;
						}
					}
					Selection::Group(name) => {
						let Some(group) = groups.iter().find(|g| &g.name == name) else {
							ui.label(egui::RichText::new("Application no longer active.").color(theme::TEXT_WEAK));
							return;
						};

						let summary = ProcessTraffic {
							pid: 0,
							name: group.name.clone(),
							download_bytes: group.download_bytes,
							upload_bytes: group.upload_bytes,
							download_speed: group.download_speed,
							upload_speed: group.upload_speed,
						};
						let subtitle = format!("{} running process(es)", group.procs.len());
						detail_header(ui, &group.name, &subtitle, &summary);

						let mut state = self.group_states.get(name).cloned().unwrap_or_default();
						let before = state.clone();
						limit_editor(ui, "group", &mut state);
						if state != before {
							// A limit set on the application replaces any
							// limit set on its single instances.
							for proc in &group.procs {
								self.pid_states.remove(&proc.pid);
							}
							self.group_states.insert(name.clone(), state);
							limits_changed = true;
							save_needed = true;
						}
					}
					Selection::Process(pid) => {
						let found = groups.iter().find_map(|g| g.procs.iter().find(|p| p.pid == *pid).map(|p| (g.name.clone(), p.clone())));
						let Some((name, proc)) = found else {
							ui.label(egui::RichText::new("Process no longer active.").color(theme::TEXT_WEAK));
							return;
						};

						detail_header(ui, &proc.name, &format!("PID {}", proc.pid), &proc);

						let mut state = self.pid_states.get(pid).cloned().or_else(|| self.group_states.get(&name).cloned()).unwrap_or_default();
						let before = state.clone();
						limit_editor(ui, "process", &mut state);
						if state != before {
							self.pid_states.insert(*pid, state);
							limits_changed = true;
						}
					}
				}
			});
		}

		// -- Central panel with table --
		let sort_column = self.sort_column;
		let sort_ascending = self.sort_ascending;
		let current = self.selection.clone();
		let expanded = self.expanded.clone();

		// The icon cache needs the context, so gather the textures up front.
		let group_icons: Vec<Option<egui::TextureHandle>> = groups
			.iter()
			.map(|group| {
				let pid = group.procs.first().map(|p| p.pid).unwrap_or(0);
				self.icons.get(ctx, &group.name, pid)
			})
			.collect();

		// Precompute the markers so the closure below does not borrow self.
		let system_flags = self.pid_states.get(&SYSTEM_PID).map(LimitFlags::of).unwrap_or_default();
		let group_flags: Vec<LimitFlags> = groups.iter().map(|g| self.flags_for_group(g)).collect();
		let child_flags: Vec<Vec<LimitFlags>> = groups.iter().map(|g| g.procs.iter().map(|p| self.flags_for_pid(p.pid, &g.name)).collect()).collect();

		egui::CentralPanel::default().frame(egui::Frame::none().fill(theme::BG_TABLE)).show(ctx, |ui| {
			ui.style_mut().interaction.selectable_labels = false;
			let available_height = ui.available_height();

			TableBuilder::new(ui)
				.striped(true)
				.resizable(true)
				.cell_layout(egui::Layout::left_to_right(egui::Align::Center))
				.min_scrolled_height(0.0)
				.max_scroll_height(available_height)
				.sense(egui::Sense::click())
				.column(Column::remainder().at_least(220.0).clip(true)) // Application
				.column(Column::initial(80.0).at_least(60.0)) // PID or instance count
				.column(Column::initial(130.0).at_least(100.0)) // Download
				.column(Column::initial(130.0).at_least(100.0)) // Upload
				.header(26.0, |mut header| {
					let columns = [
						("Application", SortColumn::Name, theme::TEXT_STRONG),
						("PID", SortColumn::Pid, theme::TEXT_STRONG),
						("Download", SortColumn::DownloadSpeed, theme::DOWNLOAD),
						("Upload", SortColumn::UploadSpeed, theme::UPLOAD),
					];
					for (label, col, color) in columns {
						header.col(|ui| {
							let bg = ui.max_rect().expand2(egui::vec2(4.0, 6.0));
							ui.painter().rect_filled(bg, 0.0, theme::BG_HEADER);
							ui.painter().hline(bg.x_range(), bg.bottom() - 0.5, egui::Stroke::new(1.0, theme::BORDER));

							let text = egui::RichText::new(label).strong().color(color);
							let mut response = ui.add(egui::Label::new(text).sense(egui::Sense::click()));
							if sort_column == col {
								response |= draw_sort_arrow(ui, sort_ascending, color);
							}
							if response.clicked() {
								clicked_column = Some(col);
							}
						});
					}
				})
				.body(|body| {
					body.rows(ROW_HEIGHT, visible.len(), |mut row| {
						let line = &visible[row.index()];

						let (name, pid_text, traffic, flags, is_child, is_selected, icon, expander) = match line {
							VisibleRow::System => ("All Traffic".to_string(), "ALL".to_string(), &system_row, system_flags, false, current == Some(Selection::System), None, None),
							VisibleRow::Group(gi) => {
								let group = &groups[*gi];
								let expandable = group.procs.len() > 1;
								(
									group.name.clone(),
									if expandable { format!("{} procs", group.procs.len()) } else { group.procs[0].pid.to_string() },
									&group.procs[0],
									group_flags[*gi],
									false,
									current == Some(Selection::Group(group.name.clone())),
									group_icons[*gi].clone(),
									if expandable { Some(expanded.contains(&group.name)) } else { None },
								)
							}
							VisibleRow::Child(gi, ci) => {
								let proc = &groups[*gi].procs[*ci];
								(proc.name.clone(), proc.pid.to_string(), proc, child_flags[*gi][*ci], true, current == Some(Selection::Process(proc.pid)), None, None)
							}
						};

						// Group rows show the sum of the whole application.
						let (dl_speed, ul_speed) = match line {
							VisibleRow::Group(gi) => (groups[*gi].download_speed, groups[*gi].upload_speed),
							_ => (traffic.download_speed, traffic.upload_speed),
						};

						if is_selected {
							row.set_selected(true);
						}

						let mut expander_clicked = false;

						// Application column
						row.col(|ui| {
							if is_child {
								// A rule that ties the child to its group.
								let rect = ui.max_rect();
								ui.painter().vline(rect.left() + 8.0, rect.y_range(), egui::Stroke::new(1.0, theme::BORDER));
								ui.add_space(16.0);
							}

							match expander {
								Some(open) => {
									if draw_expander(ui, open).clicked() {
										expander_clicked = true;
										toggle_group = Some(name.clone());
									}
								}
								None => ui.add_space(14.0),
							}

							match &icon {
								Some(texture) => {
									ui.add(egui::Image::new(texture).fit_to_exact_size(egui::vec2(ICON_SIZE, ICON_SIZE)));
								}
								None => ui.add_space(ICON_SIZE),
							}

							let mut text = egui::RichText::new(&name);
							if is_child {
								text = text.color(theme::TEXT_WEAK);
							} else if matches!(line, VisibleRow::System) {
								text = text.strong().color(theme::ACCENT_LIGHT);
							} else {
								text = text.color(theme::TEXT_STRONG);
							}
							ui.label(text);

							if flags.dl_blocked || flags.dl_active {
								let color = if flags.dl_blocked { theme::BLOCKED } else { theme::LIMITED };
								ui.label(egui::RichText::new("DL").small().strong().color(color));
							}
							if flags.ul_blocked || flags.ul_active {
								let color = if flags.ul_blocked { theme::BLOCKED } else { theme::LIMITED };
								ui.label(egui::RichText::new("UL").small().strong().color(color));
							}
						});

						// PID column
						row.col(|ui| {
							ui.label(egui::RichText::new(pid_text).color(theme::TEXT_WEAK).monospace());
						});

						// Download column
						row.col(|ui| {
							if flags.dl_blocked {
								ui.label(egui::RichText::new("BLOCKED").strong().color(theme::BLOCKED));
							} else {
								ui.label(egui::RichText::new(format_speed(dl_speed)).color(speed_color(dl_speed, theme::DOWNLOAD)).monospace());
							}
						});

						// Upload column
						row.col(|ui| {
							if flags.ul_blocked {
								ui.label(egui::RichText::new("BLOCKED").strong().color(theme::BLOCKED));
							} else {
								ui.label(egui::RichText::new(format_speed(ul_speed)).color(speed_color(ul_speed, theme::UPLOAD)).monospace());
							}
						});

						if row.response().clicked() && !expander_clicked {
							let clicked = match line {
								VisibleRow::System => Selection::System,
								VisibleRow::Group(gi) => Selection::Group(groups[*gi].name.clone()),
								VisibleRow::Child(gi, ci) => Selection::Process(groups[*gi].procs[*ci].pid),
							};
							new_selection = if is_selected { None } else { Some(clicked) };
						}
					});
				});
		});

		// Apply sort changes
		if let Some(col) = clicked_column {
			if self.sort_column == col {
				self.sort_ascending = !self.sort_ascending;
			} else {
				self.sort_column = col;
				self.sort_ascending = false;
			}
		}

		if let Some(name) = toggle_group {
			if !self.expanded.remove(&name) {
				self.expanded.insert(name);
			}
		}

		self.selection = new_selection;

		if limits_changed {
			self.apply_limits();
		}
		if save_needed {
			self.save_to_disk();
		}
	}
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

/// Draws the triangle that opens and closes a group.
fn draw_expander(ui: &mut egui::Ui, open: bool) -> egui::Response {
	let (rect, response) = ui.allocate_exact_size(egui::vec2(14.0, ROW_HEIGHT), egui::Sense::click());
	let color = if response.hovered() { theme::TEXT_STRONG } else { theme::TEXT_WEAK };
	let center = rect.center();

	let points = if open {
		vec![center + egui::vec2(-4.0, -2.0), center + egui::vec2(4.0, -2.0), center + egui::vec2(0.0, 3.0)]
	} else {
		vec![center + egui::vec2(-2.0, -4.0), center + egui::vec2(3.0, 0.0), center + egui::vec2(-2.0, 4.0)]
	};

	ui.painter().add(egui::Shape::convex_polygon(points, color, egui::Stroke::NONE));
	response
}

/// Draws the triangle that shows the sort direction of a column. The shape
/// matches the expander triangle of a grouped application.
fn draw_sort_arrow(ui: &mut egui::Ui, ascending: bool, color: egui::Color32) -> egui::Response {
	let (rect, response) = ui.allocate_exact_size(egui::vec2(12.0, ui.available_height()), egui::Sense::click());
	let center = rect.center();

	let points = if ascending {
		vec![center + egui::vec2(-4.0, 2.0), center + egui::vec2(4.0, 2.0), center + egui::vec2(0.0, -3.0)]
	} else {
		vec![center + egui::vec2(-4.0, -2.0), center + egui::vec2(4.0, -2.0), center + egui::vec2(0.0, 3.0)]
	};

	ui.painter().add(egui::Shape::convex_polygon(points, color, egui::Stroke::NONE));
	response
}

/// Draws the x that closes the detail panel. The mark is painted, not a glyph,
/// because the default fonts do not have a cross character.
fn draw_close_button(ui: &mut egui::Ui, rect: egui::Rect) -> egui::Response {
	let response = ui.allocate_rect(rect, egui::Sense::click());
	let color = if response.hovered() { theme::TEXT_STRONG } else { theme::TEXT_WEAK };
	if response.hovered() {
		ui.painter().rect_filled(rect, 0.0, theme::BG_HEADER);
	}
	let center = rect.center();
	let arm = 5.0;
	let stroke = egui::Stroke::new(1.6, color);
	ui.painter().line_segment([center + egui::vec2(-arm, -arm), center + egui::vec2(arm, arm)], stroke);
	ui.painter().line_segment([center + egui::vec2(arm, -arm), center + egui::vec2(-arm, arm)], stroke);
	response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Draws the small x that empties the search field. The mark is painted, not a
/// glyph, because the default fonts do not have a cross character.
fn draw_clear_button(ui: &mut egui::Ui, rect: egui::Rect) -> egui::Response {
	let response = ui.allocate_rect(rect, egui::Sense::click());
	let color = if response.hovered() { theme::TEXT_STRONG } else { theme::TEXT_WEAK };
	let center = rect.center();
	let arm = 4.0;
	let stroke = egui::Stroke::new(1.4, color);
	ui.painter().line_segment([center + egui::vec2(-arm, -arm), center + egui::vec2(arm, arm)], stroke);
	ui.painter().line_segment([center + egui::vec2(arm, -arm), center + egui::vec2(-arm, arm)], stroke);
	response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Shown in the detail panel while no row is selected, so the panel keeps its
/// place on screen instead of appearing over the table.
fn detail_placeholder(ui: &mut egui::Ui) {
	ui.label(egui::RichText::new("Limits").strong().size(17.0).color(theme::TEXT_STRONG));
	ui.label(egui::RichText::new("No selection").color(theme::TEXT_WEAK));
	ui.add_space(10.0);
	ui.label(egui::RichText::new("Select a row in the table to see its traffic and to set a block or a speed limit.").color(theme::TEXT_WEAK));
}

/// The title block at the top of the detail panel.
fn detail_header(ui: &mut egui::Ui, title: &str, subtitle: &str, traffic: &ProcessTraffic) {
	ui.label(egui::RichText::new(title).strong().size(17.0).color(theme::TEXT_STRONG));
	ui.label(egui::RichText::new(subtitle).color(theme::TEXT_WEAK));
	ui.add_space(8.0);

	egui::Frame::none().fill(theme::BG_TABLE).stroke(egui::Stroke::new(1.0, theme::BORDER)).inner_margin(egui::Margin::same(8.0)).show(ui, |ui| {
		ui.set_width(ui.available_width());
		stat_line(ui, "Download", format_speed(traffic.download_speed), theme::DOWNLOAD);
		stat_line(ui, "Upload", format_speed(traffic.upload_speed), theme::UPLOAD);
		ui.add_space(4.0);
		stat_line(ui, "Total down", format_bytes(traffic.download_bytes), theme::TEXT_WEAK);
		stat_line(ui, "Total up", format_bytes(traffic.upload_bytes), theme::TEXT_WEAK);
	});
	ui.add_space(10.0);
}

fn stat_line(ui: &mut egui::Ui, label: &str, value: String, color: egui::Color32) {
	ui.horizontal(|ui| {
		ui.label(egui::RichText::new(label).color(theme::TEXT_WEAK));
		ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
			ui.label(egui::RichText::new(value).strong().monospace().color(color));
		});
	});
}

/// The block of block and limit controls for one selection.
fn limit_editor(ui: &mut egui::Ui, id: &str, state: &mut ProcessLimitState) {
	section_title(ui, "Download", theme::DOWNLOAD);
	ui.checkbox(&mut state.dl_blocked, "Block all download");
	ui.add_space(2.0);
	ui.horizontal(|ui| {
		ui.checkbox(&mut state.dl_enabled, "Limit to");
		ui.add_enabled_ui(state.dl_enabled && !state.dl_blocked, |ui| {
			ui.add(egui::DragValue::new(&mut state.dl_value).speed(0.0).range(0.0..=999999.0).max_decimals(1).update_while_editing(false));
			egui::ComboBox::from_id_salt(("dl_unit", id)).selected_text(state.dl_unit.label()).width(60.0).show_ui(ui, |ui| {
				for unit in SpeedUnit::ALL {
					ui.selectable_value(&mut state.dl_unit, unit, unit.label());
				}
			});
		});
	});

	ui.add_space(14.0);

	section_title(ui, "Upload", theme::UPLOAD);
	ui.checkbox(&mut state.ul_blocked, "Block all upload");
	ui.add_space(2.0);
	ui.horizontal(|ui| {
		ui.checkbox(&mut state.ul_enabled, "Limit to");
		ui.add_enabled_ui(state.ul_enabled && !state.ul_blocked, |ui| {
			ui.add(egui::DragValue::new(&mut state.ul_value).speed(0.0).range(0.0..=999999.0).max_decimals(1).update_while_editing(false));
			egui::ComboBox::from_id_salt(("ul_unit", id)).selected_text(state.ul_unit.label()).width(60.0).show_ui(ui, |ui| {
				for unit in SpeedUnit::ALL {
					ui.selectable_value(&mut state.ul_unit, unit, unit.label());
				}
			});
		});
	});
}

/// A colored bar and a caption that start a section of the detail panel.
fn section_title(ui: &mut egui::Ui, title: &str, color: egui::Color32) {
	ui.horizontal(|ui| {
		let (rect, _) = ui.allocate_exact_size(egui::vec2(3.0, 14.0), egui::Sense::hover());
		ui.painter().rect_filled(rect, 0.0, color);
		ui.label(egui::RichText::new(title.to_uppercase()).strong().size(13.0).color(color));
	});
	ui.add_space(4.0);
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn compare_f64(a: f64, b: f64) -> std::cmp::Ordering {
	a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}

fn format_speed(bytes_per_sec: f64) -> String {
	if bytes_per_sec < 1.0 {
		"0 B/s".to_string()
	} else if bytes_per_sec < 1_024.0 {
		format!("{:.0} B/s", bytes_per_sec)
	} else if bytes_per_sec < 1_048_576.0 {
		format!("{:.1} KB/s", bytes_per_sec / 1_024.0)
	} else if bytes_per_sec < 1_073_741_824.0 {
		format!("{:.2} MB/s", bytes_per_sec / 1_048_576.0)
	} else {
		format!("{:.2} GB/s", bytes_per_sec / 1_073_741_824.0)
	}
}

fn format_bytes(bytes: u64) -> String {
	if bytes < 1_024 {
		format!("{} B", bytes)
	} else if bytes < 1_048_576 {
		format!("{:.1} KB", bytes as f64 / 1_024.0)
	} else if bytes < 1_073_741_824 {
		format!("{:.2} MB", bytes as f64 / 1_048_576.0)
	} else {
		format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
	}
}

/// Idle traffic is dimmed so that the active rows stand out.
fn speed_color(bytes_per_sec: f64, active: egui::Color32) -> egui::Color32 {
	if bytes_per_sec < 1.0 {
		theme::TEXT_WEAK.gamma_multiply(0.7)
	} else if bytes_per_sec < 10_240.0 {
		theme::TEXT
	} else {
		active
	}
}
