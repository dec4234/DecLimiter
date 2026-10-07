//! Watches the processes that show traffic, so that the list drops a process
//! the moment that the process stops.
//!
//! Windows signals a process handle when the process ends. This module opens
//! one handle for each process that we track and gives the handle to the
//! thread pool with `RegisterWaitForSingleObject`. The operating system then
//! calls [`on_exit`] as soon as the process ends. No polling is necessary.
//!
//! An open handle also stops Windows from giving the same PID to a different
//! process while we watch it, thus the PID stays unambiguous.

use log::trace;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Threading::{INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, RegisterWaitForSingleObject, UnregisterWaitEx, WT_EXECUTEONLYONCE};

/// The data that the exit callback receives.
///
/// The [`Watch`] that starts the wait keeps this box alive, and releases it
/// only after the wait is cancelled. Thus the pointer stays valid for as long
/// as the callback can run.
struct ExitContext {
	pid: u32,
	exited: Arc<Mutex<Vec<u32>>>,
}

/// One registered wait on one process.
struct Watch {
	process: HANDLE,
	wait: HANDLE,
	context: *mut ExitContext,
}

// The two handles and the context pointer belong to this structure alone, and
// the structure gives no reference to them. Thus it is safe to move it between
// threads.
unsafe impl Send for Watch {}

impl Drop for Watch {
	fn drop(&mut self) {
		unsafe {
			// INVALID_HANDLE_VALUE tells Windows to wait until the callbacks
			// that are in progress are complete. After this call no callback
			// can touch the context, thus it is safe to release it.
			let _ = UnregisterWaitEx(self.wait, Some(INVALID_HANDLE_VALUE));
			let _ = CloseHandle(self.process);
			drop(Box::from_raw(self.context));
		}
	}
}

/// The callback that Windows calls when a watched process ends.
///
/// It must do very little work, because it runs on a thread of the operating
/// system thread pool. It only records the PID; the caller of
/// [`ProcessWatcher::take_exited`] does the rest.
unsafe extern "system" fn on_exit(context: *mut c_void, _timed_out: bool) {
	if context.is_null() {
		return;
	}

	let ctx = unsafe { &*(context as *const ExitContext) };

	if let Ok(mut exited) = ctx.exited.lock() {
		exited.push(ctx.pid);
	}
}

/// Keeps one exit wait for each process that the monitor tracks.
pub struct ProcessWatcher {
	watches: Mutex<HashMap<u32, Watch>>,
	exited: Arc<Mutex<Vec<u32>>>,
}

impl ProcessWatcher {
	pub fn new() -> Self {
		Self { watches: Mutex::new(HashMap::new()), exited: Arc::new(Mutex::new(Vec::new())) }
	}

	/// Starts to watch one process.
	///
	/// Does nothing if the PID is already watched. If Windows refuses the
	/// handle, which occurs for protected processes, the process is not
	/// watched and the usual timeout removes it later.
	pub fn watch(&self, pid: u32) {
		if pid == 0 {
			return;
		}

		let mut watches = self.watches.lock().unwrap();

		if watches.contains_key(&pid) {
			return;
		}

		let process = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
			Ok(handle) => handle,
			Err(e) => {
				trace!("Cannot watch PID {pid} for exit: {e}");
				return;
			}
		};

		let context = Box::into_raw(Box::new(ExitContext { pid, exited: self.exited.clone() }));
		let mut wait = HANDLE::default();

		// If the process is already gone the handle is signalled, and Windows
		// calls the callback at once.
		let result = unsafe { RegisterWaitForSingleObject(&mut wait, process, Some(on_exit), Some(context as *const c_void), INFINITE, WT_EXECUTEONLYONCE) };

		if let Err(e) = result {
			trace!("Cannot register the exit wait for PID {pid}: {e}");
			unsafe {
				let _ = CloseHandle(process);
				drop(Box::from_raw(context));
			}
			return;
		}

		watches.insert(pid, Watch { process, wait, context });
	}

	/// Removes the PIDs of the processes that ended since the last call, and
	/// releases their waits.
	pub fn take_exited(&self) -> Vec<u32> {
		let pids = {
			let mut exited = self.exited.lock().unwrap();
			if exited.is_empty() {
				return Vec::new();
			}
			std::mem::take(&mut *exited)
		};

		for &pid in &pids {
			self.forget(pid);
		}

		pids
	}

	/// Stops the watch on one process. Use this when the process leaves the
	/// list for a different reason, for example a timeout.
	pub fn forget(&self, pid: u32) {
		// Take the watch out of the map first, then release the lock, because
		// the release of a watch waits for the callbacks that are in progress.
		let watch = self.watches.lock().unwrap().remove(&pid);
		drop(watch);
	}
}

impl Default for ProcessWatcher {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::ProcessWatcher;
	use std::time::{Duration, Instant};

	/// Starts a process, stops it, and makes sure that the watcher reports the
	/// PID without a poll of the process list.
	#[test]
	fn reports_a_process_that_ends() {
		let mut child = std::process::Command::new("cmd").args(["/c", "pause"]).stdin(std::process::Stdio::piped()).spawn().expect("cannot start the test process");
		let pid = child.id();

		let watcher = ProcessWatcher::new();
		watcher.watch(pid);

		assert!(watcher.take_exited().is_empty(), "the process still runs");

		child.kill().expect("cannot stop the test process");
		child.wait().expect("cannot collect the test process");

		let deadline = Instant::now() + Duration::from_secs(5);
		let mut exited = Vec::new();
		while Instant::now() < deadline {
			exited = watcher.take_exited();
			if !exited.is_empty() {
				break;
			}
			std::thread::sleep(Duration::from_millis(10));
		}

		assert_eq!(exited, vec![pid], "the watcher did not report the end of the process");
	}

	/// A process that ended before the watch starts must be reported too.
	#[test]
	fn reports_a_process_that_already_ended() {
		let mut child = std::process::Command::new("cmd").args(["/c", "exit"]).spawn().expect("cannot start the test process");
		let pid = child.id();
		child.wait().expect("cannot collect the test process");

		let watcher = ProcessWatcher::new();
		watcher.watch(pid);

		let deadline = Instant::now() + Duration::from_secs(5);
		let mut exited = Vec::new();
		while Instant::now() < deadline {
			exited = watcher.take_exited();
			if !exited.is_empty() {
				break;
			}
			std::thread::sleep(Duration::from_millis(10));
		}

		assert_eq!(exited, vec![pid], "the watcher did not report a process that already ended");
	}
}
