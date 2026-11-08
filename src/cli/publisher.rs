//! Lookup and caching of the publisher (company) name of a Windows executable.
//!
//! The name comes from the `CompanyName` string in the version resource of the
//! executable. Values are cached by process name, because every instance of an
//! application has the same publisher.

use std::collections::HashMap;
use std::ffi::c_void;

use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::core::PCWSTR;

use crate::cli::icons::exe_path;

/// Number of times we retry a lookup before we give up on a process name.
const MAX_ATTEMPTS: u8 = 3;

struct PublisherEntry {
	name: Option<String>,
	attempts: u8,
}

/// Cache of process-name -> publisher name.
#[derive(Default)]
pub struct PublisherCache {
	entries: HashMap<String, PublisherEntry>,
}

impl PublisherCache {
	pub fn new() -> Self {
		Self::default()
	}

	/// Returns the publisher of `name`, reading it from the executable of `pid`
	/// on the first call. Returns `None` if the file gives no publisher.
	pub fn get(&mut self, name: &str, pid: u32) -> Option<String> {
		if let Some(entry) = self.entries.get(name) {
			if entry.name.is_some() || entry.attempts >= MAX_ATTEMPTS {
				return entry.name.clone();
			}
		}

		let publisher = exe_path(pid).and_then(|path| company_name(&path));

		let entry = self.entries.entry(name.to_string()).or_insert(PublisherEntry { name: None, attempts: 0 });
		entry.attempts = entry.attempts.saturating_add(1);
		if publisher.is_some() {
			entry.name = publisher;
		}
		entry.name.clone()
	}
}

/// Reads the `CompanyName` field out of the version resource of a file.
fn company_name(path: &str) -> Option<String> {
	let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

	unsafe {
		let size = GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None);
		if size == 0 {
			return None;
		}

		let mut block = vec![0u8; size as usize];
		GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, block.as_mut_ptr() as *mut c_void).ok()?;

		// The resource holds one string table per language. Read the first
		// translation and ask for the company of that table.
		let (language, code_page) = first_translation(&block)?;
		let query: Vec<u16> = format!(r"\StringFileInfo\{language:04x}{code_page:04x}\CompanyName").encode_utf16().chain(std::iter::once(0)).collect();

		let mut value: *mut c_void = std::ptr::null_mut();
		let mut length: u32 = 0;
		if !VerQueryValueW(block.as_ptr() as *const c_void, PCWSTR(query.as_ptr()), &mut value, &mut length).as_bool() || value.is_null() || length == 0 {
			return None;
		}

		// The length counts characters and holds the final null.
		let text = std::slice::from_raw_parts(value as *const u16, length as usize);
		let text = String::from_utf16_lossy(text);
		let text = text.trim_end_matches('\0').trim().to_string();
		if text.is_empty() { None } else { Some(text) }
	}
}

/// Returns the language and code page of the first string table in `block`.
unsafe fn first_translation(block: &[u8]) -> Option<(u16, u16)> {
	unsafe {
		let query: Vec<u16> = r"\VarFileInfo\Translation".encode_utf16().chain(std::iter::once(0)).collect();

		let mut value: *mut c_void = std::ptr::null_mut();
		let mut length: u32 = 0;
		if !VerQueryValueW(block.as_ptr() as *const c_void, PCWSTR(query.as_ptr()), &mut value, &mut length).as_bool() || value.is_null() || length < 4 {
			return None;
		}

		let pair = std::slice::from_raw_parts(value as *const u16, 2);
		Some((pair[0], pair[1]))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn system_exe(name: &str) -> String {
		let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
		format!(r"{root}\System32\{name}")
	}

	#[test]
	fn company_of_a_windows_executable_is_microsoft() {
		let company = company_name(&system_exe("notepad.exe")).expect("notepad must have a company name");
		assert!(company.contains("Microsoft"), "{company}");
		assert_eq!(company, company.trim(), "the name must have no extra space");
		assert!(!company.contains('\0'));
	}

	#[test]
	fn company_of_a_missing_file_is_none() {
		assert_eq!(company_name(r"C:\no\such\dir\declimiter-test.exe"), None);
	}

	#[test]
	fn cache_gives_up_after_the_maximum_attempts() {
		let mut cache = PublisherCache::new();
		for _ in 0..MAX_ATTEMPTS + 2 {
			assert_eq!(cache.get("ghost.exe", 0), None);
		}
		assert_eq!(cache.entries["ghost.exe"].attempts, MAX_ATTEMPTS);
	}

	#[test]
	fn cache_keeps_a_found_name() {
		let mut child = std::process::Command::new(system_exe("cmd.exe")).args(["/c", "pause"]).stdin(std::process::Stdio::piped()).spawn().expect("cannot start cmd");

		let mut cache = PublisherCache::new();
		let first = cache.get("cmd.exe", child.id());
		child.kill().unwrap();
		child.wait().unwrap();

		let first = first.expect("cmd.exe must have a publisher");
		assert!(first.contains("Microsoft"), "{first}");

		// The process is gone, but the cache still answers without a new lookup.
		assert_eq!(cache.get("cmd.exe", 0), Some(first));
		assert_eq!(cache.entries["cmd.exe"].attempts, 1);
	}
}
