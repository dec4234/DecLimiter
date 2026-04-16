use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use declimiter_lib::limiter::{DecLimiter, LimitConfig, LimitsMap, ProcessTraffic};
use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::config::{self, ProcessConfig, ProcessesConfig};

const SYSTEM_PID: u32 = 0;

/// Launch the GUI network monitor window.
pub fn launch_gui() {
	simple_logger::init_with_level(log::Level::Debug).ok();

	let stats: Arc<Mutex<Vec<ProcessTraffic>>> = Arc::new(Mutex::new(Vec::new()));
	let system_totals: Arc<Mutex<ProcessTraffic>> = Arc::new(Mutex::new(ProcessTraffic {
		pid: 0, name: "System".to_string(), download_bytes: 0, upload_bytes: 0, download_speed: 0.0, upload_speed: 0.0,
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
					*error_bg.lock().unwrap() = Some(format!(
						"Failed to initialize: {}\n\nMake sure:\n1. WinpkFilter driver is installed\n2. Running as Administrator",
						e
					));
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
		viewport: egui::ViewportBuilder::default()
			.with_inner_size([900.0, 600.0])
			.with_title("DecLimiter")
			.with_icon(Arc::new(icon)),
		..Default::default()
	};

	// Load saved process configs and app config from disk
	config::load_app_config();
	let saved_processes = config::load_processes_config();

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
				limit_states: HashMap::new(),
				sort_column: SortColumn::DownloadSpeed,
				sort_ascending: false,
				search_query: String::new(),
				selected_pid: None,
				saved_processes,
				known_pids: HashMap::new(),
			}))
		}),
	)
	.unwrap();
}

fn configure_style(ctx: &egui::Context) {
	ctx.set_visuals(egui::Visuals::dark());
	let mut style = (*ctx.style()).clone();
	style.spacing.item_spacing = egui::vec2(8.0, 4.0);
	ctx.set_style(style);
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
		self.dl_enabled || self.dl_blocked || self.dl_value > 0.0
			|| self.ul_enabled || self.ul_blocked || self.ul_value > 0.0
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
	limit_states: HashMap<u32, ProcessLimitState>,
	sort_column: SortColumn,
	sort_ascending: bool,
	search_query: String,
	selected_pid: Option<u32>,
	/// Saved process configs loaded from disk, keyed by process name.
	saved_processes: ProcessesConfig,
	/// Tracks which process names we've already restored settings for (by PID).
	known_pids: HashMap<u32, String>,
}

impl DecLimiterApp {
	fn sort_stats(&self, stats: &mut [ProcessTraffic]) {
		let ascending = self.sort_ascending;
		stats.sort_by(|a, b| {
			let ord = match self.sort_column {
				SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
				SortColumn::Pid => a.pid.cmp(&b.pid),
				SortColumn::DownloadSpeed => a.download_speed.partial_cmp(&b.download_speed).unwrap_or(std::cmp::Ordering::Equal),
				SortColumn::UploadSpeed => a.upload_speed.partial_cmp(&b.upload_speed).unwrap_or(std::cmp::Ordering::Equal),
			};
			if ascending { ord } else { ord.reverse() }
		});
	}

	fn apply_limits(&self) {
		let handle_lock = self.limits_handle.lock().unwrap();
		let Some(limits) = handle_lock.as_ref() else { return };
		let mut limits_lock = limits.write().unwrap();
		limits_lock.clear();
		for (&pid, state) in &self.limit_states {
			let dl = state.download_byterate();
			let ul = state.upload_byterate();
			if dl.is_some() || ul.is_some() {
				limits_lock.insert(pid, LimitConfig {
					download_byterate: dl,
					upload_byterate: ul,
				});
			}
		}
	}

	/// Save current limit states to disk, keyed by process name.
	fn save_to_disk(&mut self) {
		for (&pid, state) in &self.limit_states {
			if let Some(name) = self.known_pids.get(&pid) {
				if state.has_any_setting() {
					self.saved_processes.insert(name.clone(), state.to_process_config());
				} else {
					self.saved_processes.remove(name);
				}
			}
		}
		config::save_processes_config(&self.saved_processes);
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
					ui.heading(egui::RichText::new("Monitor Error").color(egui::Color32::RED).size(24.0));
					ui.add_space(20.0);
					ui.label(egui::RichText::new(err).size(16.0));
				});
			});
			return;
		}

		let mut stats = self.stats.lock().unwrap().clone();

		// Restore saved settings for any newly-seen processes
		let mut restored_any = false;
		for proc in &stats {
			if proc.pid == SYSTEM_PID {
				continue;
			}
			if !self.known_pids.contains_key(&proc.pid) {
				self.known_pids.insert(proc.pid, proc.name.clone());
				if let Some(saved) = self.saved_processes.get(&proc.name) {
					let state = ProcessLimitState::from_process_config(saved);
					if state.has_any_setting() {
						self.limit_states.insert(proc.pid, state);
						restored_any = true;
					}
				}
			}
		}
		if restored_any {
			self.apply_limits();
		}

		// Filter by search query
		if !self.search_query.is_empty() {
			let query = self.search_query.to_lowercase();
			stats.retain(|s| s.name.to_lowercase().contains(&query) || s.pid.to_string().contains(&query));
		}

		// Use real total traffic counters for the System row
		let system_row = self.system_totals.lock().unwrap().clone();
		self.sort_stats(&mut stats);

		// Combine: System always first
		let mut all_rows = Vec::with_capacity(stats.len() + 1);
		all_rows.push(system_row);
		all_rows.extend(stats);

		// Pre-compute limit status for each PID (read-only snapshot for table rendering)
		let limit_indicators: HashMap<u32, (bool, bool, bool, bool)> = self.limit_states.iter()
			.map(|(&pid, s)| (pid, (s.dl_active(), s.ul_active(), s.dl_blocked, s.ul_blocked)))
			.collect();

		let mut clicked_column: Option<SortColumn> = None;
		let mut new_selected = self.selected_pid;
		let mut limits_changed = false;

		// -- Top panel --
		egui::TopBottomPanel::top("header").show(ctx, |ui| {
			ui.add_space(4.0);
			ui.horizontal(|ui| {
				ui.heading("DecLimiter");
				ui.separator();
				ui.label("Network Monitor");
				ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
					ui.label(format!("{} processes", all_rows.len() - 1));
				});
			});
			ui.add_space(2.0);
			ui.horizontal(|ui| {
				ui.label("Search:");
				ui.add(egui::TextEdit::singleline(&mut self.search_query).desired_width(200.0).hint_text("Filter by name or PID..."));
				if ui.button("Clear").clicked() {
					self.search_query.clear();
				}
			});
			ui.add_space(4.0);
		});

		// -- Right detail panel --
		if let Some(sel_pid) = self.selected_pid {
			let sel_stat = all_rows.iter().find(|s| s.pid == sel_pid).cloned();
			let state = self.limit_states.entry(sel_pid).or_insert_with(ProcessLimitState::default);
			let state_before = state.clone();

			egui::SidePanel::right("details").min_width(260.0).max_width(300.0).show(ctx, |ui| {
				if let Some(stat) = &sel_stat {
					// Header
					ui.heading(egui::RichText::new(&stat.name).strong());
					if sel_pid == SYSTEM_PID {
						ui.label("All network traffic");
					} else {
						ui.label(format!("PID: {}", stat.pid));
					}
					ui.add_space(4.0);
					ui.horizontal(|ui| {
						ui.label(format!("DL: {}", format_speed(stat.download_speed)));
						ui.separator();
						ui.label(format!("UL: {}", format_speed(stat.upload_speed)));
					});
					ui.add_space(2.0);
					ui.horizontal(|ui| {
						ui.label(format!("Total DL: {}", format_bytes(stat.download_bytes)));
						ui.separator();
						ui.label(format!("Total UL: {}", format_bytes(stat.upload_bytes)));
					});
					ui.separator();

					// -- Download --
					ui.add_space(8.0);
					ui.label(egui::RichText::new("DL  Download").strong().size(15.0).color(egui::Color32::from_rgb(100, 200, 255)));
					ui.add_space(4.0);

					ui.checkbox(&mut state.dl_blocked, "Block All Download");

					ui.add_space(4.0);
					ui.horizontal(|ui| {
						ui.checkbox(&mut state.dl_enabled, "Limit");
						ui.add_enabled_ui(state.dl_enabled && !state.dl_blocked, |ui| {
							ui.add(egui::DragValue::new(&mut state.dl_value).speed(0.0).range(0.0..=999999.0).max_decimals(1).update_while_editing(false));
							egui::ComboBox::from_id_salt(("dl_unit_panel", sel_pid))
								.selected_text(state.dl_unit.label())
								.width(50.0)
								.show_ui(ui, |ui| {
									for u in SpeedUnit::ALL {
										ui.selectable_value(&mut state.dl_unit, u, u.label());
									}
								});
						});
					});

					ui.add_space(16.0);

					// -- Upload --
					ui.label(egui::RichText::new("UL  Upload").strong().size(15.0).color(egui::Color32::from_rgb(255, 180, 100)));
					ui.add_space(4.0);

					ui.checkbox(&mut state.ul_blocked, "Block All Upload");

					ui.add_space(4.0);
					ui.horizontal(|ui| {
						ui.checkbox(&mut state.ul_enabled, "Limit");
						ui.add_enabled_ui(state.ul_enabled && !state.ul_blocked, |ui| {
							ui.add(egui::DragValue::new(&mut state.ul_value).speed(0.0).range(0.0..=999999.0).max_decimals(1).update_while_editing(false));
							egui::ComboBox::from_id_salt(("ul_unit_panel", sel_pid))
								.selected_text(state.ul_unit.label())
								.width(50.0)
								.show_ui(ui, |ui| {
									for u in SpeedUnit::ALL {
										ui.selectable_value(&mut state.ul_unit, u, u.label());
									}
								});
						});
					});

					ui.add_space(16.0);
					ui.separator();
					if ui.button("Close").clicked() {
						new_selected = None;
					}
				} else {
					ui.label("Process no longer active.");
					if ui.button("Close").clicked() {
						new_selected = None;
					}
				}
			});

			limits_changed = *state != state_before;
		}

		// -- Central panel with table --
		let sort_column = self.sort_column;
		let sort_ascending = self.sort_ascending;
		let current_selected = self.selected_pid;

		egui::CentralPanel::default().show(ctx, |ui| {
			ui.style_mut().interaction.selectable_labels = false;
			let available_height = ui.available_height();

			TableBuilder::new(ui)
				.striped(true)
				.resizable(true)
				.cell_layout(egui::Layout::left_to_right(egui::Align::Center))
				.min_scrolled_height(0.0)
				.max_scroll_height(available_height)
				.sense(egui::Sense::click())
				.column(Column::auto().at_least(180.0).clip(true)) // Process
				.column(Column::auto().at_least(60.0))             // PID
				.column(Column::auto().at_least(120.0))            // Download
				.column(Column::auto().at_least(120.0))            // Upload
				.header(22.0, |mut header| {
					let columns = [
						("Process", SortColumn::Name),
						("PID", SortColumn::Pid),
						("DL  Download", SortColumn::DownloadSpeed),
						("UL  Upload", SortColumn::UploadSpeed),
					];
					for (label, col) in columns {
						header.col(|ui| {
							let arrow = if sort_column == col {
								if sort_ascending { " ^" } else { " v" }
							} else {
								""
							};
							let text = format!("{label}{arrow}");
							if ui
								.add(egui::Label::new(egui::RichText::new(text).strong().color(egui::Color32::WHITE)).sense(egui::Sense::click()))
								.clicked()
							{
								clicked_column = Some(col);
							}
						});
					}
				})
				.body(|body| {
					body.rows(22.0, all_rows.len(), |mut row| {
						let idx = row.index();
						let stat = &all_rows[idx];
						let pid = stat.pid;
						let is_system = pid == SYSTEM_PID;
						let is_selected = current_selected == Some(pid);

						if is_selected {
							row.set_selected(true);
						}

						// Process name column
						row.col(|ui| {
							let (dl_active, ul_active, dl_blocked, ul_blocked) = limit_indicators.get(&pid).copied().unwrap_or_default();

							let mut text = egui::RichText::new(&stat.name);
							if is_system {
								text = text.strong();
							}

							ui.label(text);

							// Limit indicator icons
							if dl_blocked {
								ui.label(egui::RichText::new("DL").small().color(egui::Color32::RED));
							} else if dl_active {
								ui.label(egui::RichText::new("DL").small().color(egui::Color32::YELLOW));
							}
							if ul_blocked {
								ui.label(egui::RichText::new("UL").small().color(egui::Color32::RED));
							} else if ul_active {
								ui.label(egui::RichText::new("UL").small().color(egui::Color32::YELLOW));
							}
						});

						// PID column
						row.col(|ui| {
							if is_system {
								ui.label(egui::RichText::new("ALL").strong());
							} else {
								ui.label(pid.to_string());
							}
						});

						// Download speed column
						row.col(|ui| {
							let (_, _, dl_blocked, _) = limit_indicators.get(&pid).copied().unwrap_or_default();
							if dl_blocked {
								ui.label(egui::RichText::new("BLOCKED").color(egui::Color32::RED));
							} else {
								let color = speed_color(stat.download_speed);
								ui.label(egui::RichText::new(format_speed(stat.download_speed)).color(color));
							}
						});

						// Upload speed column
						row.col(|ui| {
							let (_, _, _, ul_blocked) = limit_indicators.get(&pid).copied().unwrap_or_default();
							if ul_blocked {
								ui.label(egui::RichText::new("BLOCKED").color(egui::Color32::RED));
							} else {
								let color = speed_color(stat.upload_speed);
								ui.label(egui::RichText::new(format_speed(stat.upload_speed)).color(color));
							}
						});

						// Row click detection
						if row.response().clicked() {
							new_selected = if is_selected { None } else { Some(pid) };
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

		self.selected_pid = new_selected;

		if limits_changed {
			self.apply_limits();
			self.save_to_disk();
		}
	}
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

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

fn speed_color(bytes_per_sec: f64) -> egui::Color32 {
	if bytes_per_sec < 1.0 {
		egui::Color32::GRAY
	} else if bytes_per_sec < 10_240.0 {
		egui::Color32::LIGHT_GRAY
	} else if bytes_per_sec < 1_048_576.0 {
		egui::Color32::from_rgb(100, 200, 255)
	} else {
		egui::Color32::from_rgb(100, 255, 100)
	}
}
