//! Component UI tests. They run the interface without a window, find widgets
//! through the AccessKit tree, and click or type the way a user does.
//!
//! The PIDs in these tests are odd numbers. Windows PIDs are always multiples
//! of four, so the icon and publisher lookups never find a real process.

use super::*;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ZOOM: u32 = 900_001;
const CHROME_A: u32 = 900_003;
const CHROME_B: u32 = 900_005;
const CHROME_C: u32 = 900_007;
const APEX: u32 = 900_009;

fn proc(pid: u32, name: &str, download_speed: f64, upload_speed: f64) -> ProcessTraffic {
	ProcessTraffic {
		pid,
		name: name.to_string(),
		download_bytes: 0,
		upload_bytes: 0,
		download_speed,
		upload_speed,
	}
}

/// Three applications. Chrome has three instances.
fn sample_stats() -> Vec<ProcessTraffic> {
	vec![
		proc(CHROME_A, "chrome.exe", 100.0, 5.0),
		proc(ZOOM, "Zoom.exe", 50.0, 500.0),
		proc(CHROME_B, "chrome.exe", 300.0, 1.0),
		proc(APEX, "apex.exe", 10.0, 50.0),
		proc(CHROME_C, "chrome.exe", 0.0, 2.0),
	]
}

fn test_app(stats: Vec<ProcessTraffic>) -> DecLimiterApp {
	DecLimiterApp::new(
		Arc::new(Mutex::new(stats)),
		Arc::new(Mutex::new(proc(0, "System", 2048.0, 1024.0))),
		Arc::new(Mutex::new(None)),
		Arc::new(Mutex::new(Startup::Ready)),
		Arc::new(Mutex::new(None)),
		Arc::new(Mutex::new(Vec::new())),
		HashMap::new(),
		false,
	)
}

/// Runs the full application at the default window size.
fn app_harness(app: DecLimiterApp) -> Harness<'static, DecLimiterApp> {
	let mut harness = Harness::builder().with_size(egui::vec2(980.0, 620.0)).build_eframe(|cc| {
		configure_style(&cc.egui_ctx);
		app
	});
	harness.run();
	harness
}

/// The vertical position of the first widget with this label.
fn top_of(harness: &Harness<'_, DecLimiterApp>, label: &str) -> f32 {
	harness.get_all_by_label(label).next().unwrap_or_else(|| panic!("no widget labelled {label:?}")).rect().top()
}

/// Clicks the first widget with this label.
fn click_first(harness: &mut Harness<'_, DecLimiterApp>, label: &str) {
	harness.get_all_by_label(label).next().unwrap_or_else(|| panic!("no widget labelled {label:?}")).click();
	harness.run();
}

/// Clicks the table row with this name. The detail panel can show the same
/// name as its title, so the label farthest to the left is the one in the table.
fn click_row(harness: &mut Harness<'_, DecLimiterApp>, label: &str) {
	harness
		.get_all_by_label(label)
		.min_by(|a, b| a.rect().left().total_cmp(&b.rect().left()))
		.unwrap_or_else(|| panic!("no row labelled {label:?}"))
		.click();
	harness.run();
}

fn type_into_search(harness: &mut Harness<'_, DecLimiterApp>, text: &str) {
	let field = harness.get_by_role(Role::TextInput);
	field.focus();
	field.type_text(text);
	harness.run();
}

// ---------------------------------------------------------------------------
// Limit editor component
// ---------------------------------------------------------------------------

fn editor_harness(state: ProcessLimitState) -> Harness<'static, ProcessLimitState> {
	let mut harness = Harness::builder().with_size(egui::vec2(320.0, 300.0)).build_ui_state(|ui, state: &mut ProcessLimitState| limit_editor(ui, "test", state), state);
	harness.run();
	harness
}

const DL_VALUE: &str = "Download limit value";
const UL_VALUE: &str = "Upload limit value";

/// Replaces the text of the named value field and confirms it with Enter.
fn enter_value(harness: &mut Harness<'_, ProcessLimitState>, field_name: &str, text: &str) {
	let field = harness.get_by_label(field_name);
	field.focus();
	harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
	field.type_text(text);
	harness.run();
	// Enter takes the focus away from the field, and only then the value applies.
	harness.key_press(egui::Key::Enter);
	harness.run();
}

#[test]
fn limit_editor_shows_both_sections() {
	let harness = editor_harness(ProcessLimitState::default());
	harness.get_by_label("DOWNLOAD");
	harness.get_by_label("UPLOAD");
	harness.get_by_role_and_label(Role::CheckBox, "Block all download");
	harness.get_by_role_and_label(Role::CheckBox, "Block all upload");
	assert_eq!(harness.get_all_by_role_and_label(Role::CheckBox, "Limit to").count(), 2);
	harness.get_by_role_and_label(Role::TextInput, DL_VALUE);
	harness.get_by_role_and_label(Role::TextInput, UL_VALUE);
	harness.get_by_role_and_label(Role::ComboBox, "Download limit unit");
	harness.get_by_role_and_label(Role::ComboBox, "Upload limit unit");
}

#[test]
fn block_check_boxes_change_the_state() {
	let mut harness = editor_harness(ProcessLimitState::default());

	harness.get_by_label("Block all download").click();
	harness.run();
	assert!(harness.state().dl_blocked);
	assert!(!harness.state().ul_blocked);

	harness.get_by_label("Block all upload").click();
	harness.run();
	assert!(harness.state().ul_blocked);
	assert_eq!(harness.state().download_byterate(), Some(0));
	assert_eq!(harness.state().upload_byterate(), Some(0));

	harness.get_by_label("Block all download").click();
	harness.run();
	assert!(!harness.state().dl_blocked);
}

#[test]
fn value_field_is_disabled_until_the_limit_is_enabled() {
	let mut harness = editor_harness(ProcessLimitState::default());

	enter_value(&mut harness, DL_VALUE, "250");
	assert_eq!(harness.state().dl_value, 0.0, "a disabled field must not accept a value");

	harness.get_all_by_label("Limit to").next().unwrap().click();
	harness.run();
	assert!(harness.state().dl_enabled);

	enter_value(&mut harness, DL_VALUE, "250");
	assert_eq!(harness.state().dl_value, 250.0);
	assert_eq!(harness.state().download_byterate(), Some(250 * 1024));
	assert_eq!(harness.state().ul_value, 0.0, "the upload value must not change");
}

#[test]
fn value_field_rounds_clamps_and_ignores_bad_text() {
	let mut harness = editor_harness(ProcessLimitState {
		dl_enabled: true,
		dl_value: 5.0,
		..Default::default()
	});

	enter_value(&mut harness, DL_VALUE, "12.34");
	assert_eq!(harness.state().dl_value, 12.3);

	enter_value(&mut harness, DL_VALUE, "not a number");
	assert_eq!(harness.state().dl_value, 12.3, "bad text keeps the old value");

	enter_value(&mut harness, DL_VALUE, "-40");
	assert_eq!(harness.state().dl_value, 0.0);

	enter_value(&mut harness, DL_VALUE, "5000000");
	assert_eq!(harness.state().dl_value, 999_999.0);
}

#[test]
fn value_field_shows_the_current_value() {
	let harness = editor_harness(ProcessLimitState {
		dl_value: 2.5,
		ul_value: 100.0,
		..Default::default()
	});
	assert_eq!(harness.get_by_label(DL_VALUE).value().as_deref(), Some("2.5"));
	assert_eq!(harness.get_by_label(UL_VALUE).value().as_deref(), Some("100"));
}

#[test]
fn unit_combo_box_changes_the_unit() {
	let mut harness = editor_harness(ProcessLimitState {
		ul_enabled: true,
		ul_value: 2.0,
		..Default::default()
	});

	harness.get_by_label("Upload limit unit").click();
	harness.run();
	harness.get_by_label("MB/s").click();
	harness.run();

	assert!(harness.state().ul_unit == SpeedUnit::MBps);
	assert!(harness.state().dl_unit == SpeedUnit::KBps);
	assert_eq!(harness.state().upload_byterate(), Some(2 * 1_048_576));
}

// ---------------------------------------------------------------------------
// Detail panel components
// ---------------------------------------------------------------------------

#[test]
fn detail_header_shows_formatted_traffic() {
	let traffic = ProcessTraffic {
		pid: ZOOM,
		name: "Zoom.exe".to_string(),
		download_bytes: 3 * 1_048_576,
		upload_bytes: 512,
		download_speed: 1536.0,
		upload_speed: 0.0,
	};
	let harness = Harness::builder().with_size(egui::vec2(320.0, 300.0)).build_ui(|ui| detail_header(ui, "Zoom.exe", "PID 900001", &traffic));

	harness.get_by_label("Zoom.exe");
	harness.get_by_label("PID 900001");
	harness.get_by_label("1.5 KB/s");
	harness.get_by_label("0 B/s");
	harness.get_by_label("3.00 MB");
	harness.get_by_label("512 B");
}

#[test]
fn detail_placeholder_asks_for_a_selection() {
	let harness = Harness::new_ui(detail_placeholder);
	harness.get_by_label("Limits");
	harness.get_by_label("No selection");
}

// ---------------------------------------------------------------------------
// Full application
// ---------------------------------------------------------------------------

#[test]
fn table_lists_one_row_per_application() {
	let harness = app_harness(test_app(sample_stats()));

	harness.get_by_label("All Traffic");
	harness.get_by_label("chrome.exe");
	harness.get_by_label("Zoom.exe");
	harness.get_by_label("apex.exe");
	harness.get_by_label("3 procs");
	harness.get_by_label("3 apps / 5 processes");
	harness.get_by_label("No selection");

	// Instances stay hidden until the group opens.
	assert!(harness.query_by_label(&CHROME_A.to_string()).is_none());
	// A single instance application shows its PID.
	harness.get_by_label(&ZOOM.to_string());
}

#[test]
fn status_bar_shows_the_system_totals() {
	let harness = app_harness(test_app(sample_stats()));
	// The totals show in the status bar and in the "All Traffic" row.
	assert_eq!(harness.get_all_by_label("2.0 KB/s").count(), 2);
	assert_eq!(harness.get_all_by_label("1.0 KB/s").count(), 2);
	harness.get_by_label("0 rules active");
}

#[test]
fn table_sorts_by_download_speed_first() {
	let harness = app_harness(test_app(sample_stats()));
	assert!(top_of(&harness, "chrome.exe") < top_of(&harness, "Zoom.exe"));
	assert!(top_of(&harness, "Zoom.exe") < top_of(&harness, "apex.exe"));
}

#[test]
fn column_header_click_changes_the_sort() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_first(&mut harness, "Application");
	assert!(harness.state().sort_column == SortColumn::Name);
	assert!(!harness.state().sort_ascending);
	assert!(top_of(&harness, "Zoom.exe") < top_of(&harness, "chrome.exe"));
	assert!(top_of(&harness, "chrome.exe") < top_of(&harness, "apex.exe"));

	click_first(&mut harness, "Application");
	assert!(harness.state().sort_ascending);
	assert!(top_of(&harness, "apex.exe") < top_of(&harness, "chrome.exe"));

	click_first(&mut harness, "Upload");
	assert!(harness.state().sort_column == SortColumn::UploadSpeed);
	assert!(top_of(&harness, "Zoom.exe") < top_of(&harness, "apex.exe"));
}

#[test]
fn search_filters_by_name() {
	let mut harness = app_harness(test_app(sample_stats()));

	type_into_search(&mut harness, "ZOOM");
	harness.get_by_label("Zoom.exe");
	assert!(harness.query_by_label("chrome.exe").is_none());
	assert!(harness.query_by_label("apex.exe").is_none());
	harness.get_by_label("1 apps / 1 processes");
	// The system row is always visible.
	harness.get_by_label("All Traffic");
}

#[test]
fn search_filters_by_pid() {
	let mut harness = app_harness(test_app(sample_stats()));

	type_into_search(&mut harness, &CHROME_B.to_string());
	harness.get_by_label("chrome.exe");
	assert!(harness.query_by_label("Zoom.exe").is_none());
	harness.get_by_label("1 apps / 1 processes");
}

#[test]
fn expand_and_collapse_all() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_first(&mut harness, "Expand all");
	for pid in [CHROME_A, CHROME_B, CHROME_C] {
		harness.get_by_label(&pid.to_string());
	}
	// The instances sit below their application.
	assert!(top_of(&harness, "3 procs") < top_of(&harness, &CHROME_B.to_string()));

	click_first(&mut harness, "Collapse all");
	assert!(harness.query_by_label(&CHROME_A.to_string()).is_none());
	assert!(harness.state().expanded.is_empty());
}

#[test]
fn clicking_a_row_selects_it_and_a_second_click_clears_it() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_row(&mut harness, "chrome.exe");
	assert!(harness.state().selection == Some(Selection::Group("chrome.exe".to_string())));
	harness.get_by_label("3 running process(es)");
	harness.get_by_label("Block all download");
	assert!(harness.query_by_label("No selection").is_none());

	click_row(&mut harness, "chrome.exe");
	assert!(harness.state().selection.is_none());
	harness.get_by_label("No selection");
}

#[test]
fn selecting_an_instance_shows_its_pid() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_first(&mut harness, "Expand all");
	click_row(&mut harness, &CHROME_C.to_string());
	assert!(harness.state().selection == Some(Selection::Process(CHROME_C)));
	harness.get_by_label(&format!("PID {CHROME_C}"));
}

#[test]
fn selecting_the_system_row_shows_all_traffic() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_row(&mut harness, "All Traffic");
	assert!(harness.state().selection == Some(Selection::System));
	harness.get_by_label("Every process on this machine");
}

#[test]
fn blocking_a_group_marks_the_row_and_pushes_the_limit() {
	let app = test_app(sample_stats());
	let limits: LimitsMap = Arc::new(std::sync::RwLock::new(HashMap::new()));
	*app.limits_handle.lock().unwrap() = Some(limits.clone());
	let mut harness = app_harness(app);

	click_row(&mut harness, "chrome.exe");
	harness.get_by_label("Block all download").click();
	harness.run();

	assert!(harness.state().group_states["chrome.exe"].dl_blocked);
	harness.get_by_label("BLOCKED");
	harness.get_by_label("1 rules active");

	let map = limits.read().unwrap();
	for pid in [CHROME_A, CHROME_B, CHROME_C] {
		assert_eq!(map[&pid].download_byterate, Some(0), "pid {pid}");
		assert_eq!(map[&pid].upload_byterate, None, "pid {pid}");
	}
	assert!(!map.contains_key(&ZOOM));
}

#[test]
fn a_group_limit_removes_the_instance_overrides() {
	let mut app = test_app(sample_stats());
	app.pid_states.insert(CHROME_A, ProcessLimitState { ul_blocked: true, ..Default::default() });
	let mut harness = app_harness(app);

	click_row(&mut harness, "chrome.exe");
	harness.get_by_label("Block all upload").click();
	harness.run();

	assert!(!harness.state().pid_states.contains_key(&CHROME_A));
	assert!(harness.state().group_states["chrome.exe"].ul_blocked);
}

#[test]
fn context_menu_pins_a_row_to_the_top() {
	let mut harness = app_harness(test_app(sample_stats()));
	assert!(top_of(&harness, "chrome.exe") < top_of(&harness, "apex.exe"));

	harness.get_by_label("apex.exe").click_secondary();
	harness.run();
	harness.get_by_label("Pin to top").click();
	harness.run();

	assert!(harness.state().pins == vec![PinTarget::Group("apex.exe".to_string())]);
	assert!(top_of(&harness, "apex.exe") < top_of(&harness, "chrome.exe"));

	harness.get_by_label("apex.exe").click_secondary();
	harness.run();
	harness.get_by_label("Unpin").click();
	harness.run();
	assert!(harness.state().pins.is_empty());
}

#[test]
fn holding_ctrl_holds_the_row_order() {
	let mut harness = app_harness(test_app(sample_stats()));
	assert!(top_of(&harness, "chrome.exe") < top_of(&harness, "apex.exe"));

	harness.event(egui::Event::ModifiersChanged(egui::Modifiers::CTRL));
	harness.run();
	harness.get_by_label("Order held (Ctrl)");

	// apex.exe becomes the fastest application, but the rows must not move.
	harness.state().stats.lock().unwrap()[3].download_speed = 1_000_000.0;
	harness.run();
	assert!(top_of(&harness, "chrome.exe") < top_of(&harness, "apex.exe"));

	harness.event(egui::Event::ModifiersChanged(egui::Modifiers::NONE));
	harness.run();
	assert!(harness.query_by_label("Order held (Ctrl)").is_none());
	assert!(top_of(&harness, "apex.exe") < top_of(&harness, "chrome.exe"));
}

#[test]
fn an_exited_process_leaves_the_table_and_the_selection() {
	let mut harness = app_harness(test_app(sample_stats()));

	click_row(&mut harness, "Zoom.exe");
	assert!(harness.state().selection == Some(Selection::Group("Zoom.exe".to_string())));

	harness.state().exited.lock().unwrap().push(ZOOM);
	harness.run();

	assert!(harness.query_by_label("Zoom.exe").is_none());
	harness.get_by_label("2 apps / 4 processes");
	harness.get_by_label("Application no longer active.");
}

#[test]
fn monitor_error_replaces_the_table() {
	let app = test_app(sample_stats());
	*app.monitor_error.lock().unwrap() = Some("Driver not found".to_string());
	let harness = app_harness(app);

	harness.get_by_label("Monitor Error");
	harness.get_by_label("Driver not found");
	assert!(harness.query_by_label("chrome.exe").is_none());
}

#[test]
fn startup_status_replaces_the_table() {
	let app = test_app(sample_stats());
	*app.startup.lock().unwrap() = Startup::Busy("Installing the driver".to_string());
	// The spinner repaints all the time, thus run a fixed number of frames.
	let mut harness = Harness::builder().with_size(egui::vec2(980.0, 620.0)).build_eframe(|cc| {
		configure_style(&cc.egui_ctx);
		app
	});
	harness.run_steps(2);

	harness.get_by_label("Installing the driver");
	assert!(harness.query_by_label("chrome.exe").is_none());
}

/// Shows the install prompt and returns the receiver of the answer.
fn install_prompt_harness() -> (Harness<'static, DecLimiterApp>, std::sync::mpsc::Receiver<bool>) {
	let app = test_app(sample_stats());
	let (answer, reply) = std::sync::mpsc::channel();
	*app.startup.lock().unwrap() = Startup::AskInstall(answer);
	let mut harness = Harness::builder().with_size(egui::vec2(980.0, 620.0)).build_eframe(|cc| {
		configure_style(&cc.egui_ctx);
		app
	});
	harness.run_steps(2);
	(harness, reply)
}

#[test]
fn install_prompt_replaces_the_table() {
	let (harness, reply) = install_prompt_harness();
	harness.get_by_label("Driver Required");
	harness.get_by_label_contains("github.com/wiresock/ndisapi");
	assert!(harness.query_by_label("chrome.exe").is_none());
	assert!(reply.try_recv().is_err(), "no answer must be sent before a click");
}

#[test]
fn install_button_sends_yes() {
	let (mut harness, reply) = install_prompt_harness();
	harness.get_by_label("Install").click();
	harness.run_steps(2);

	assert_eq!(reply.try_recv(), Ok(true));
	assert!(harness.query_by_label("Driver Required").is_none());
	harness.get_by_label("Please wait...");
}

#[test]
fn cancel_button_sends_no() {
	let (mut harness, reply) = install_prompt_harness();
	harness.get_by_label("Cancel").click();
	harness.run_steps(2);

	assert_eq!(reply.try_recv(), Ok(false));
	assert!(harness.query_by_label("Driver Required").is_none());
}
