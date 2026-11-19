use regex_cache::{CachedRegex, CachedRegexBuilder, RegexCache};
use std::sync::{Arc, Mutex};

#[test]
fn cached_methods_match_uncached_regex() {
	for pattern in [
		r"(?P<word>[A-Za-z]+)-(?P<n>\d+)",
		r"(?P<han>[\p{Han}]+)",
		r"^\d+$",
		r"a*",
	] {
		let cache = Arc::new(Mutex::new(RegexCache::new(100)));
		let re = CachedRegex::new(cache.clone(), pattern).unwrap();
		let direct = regex::Regex::new(pattern).unwrap();
		for text in ["abc-123 zz-9", "张三😀李四", "1111111111", "", "nothing"] {
			assert_eq!(re.is_match(text), direct.is_match(text));
			assert_eq!(
				re.find(text).map(|m| (m.start(), m.end())),
				direct.find(text).map(|m| (m.start(), m.end()))
			);
			let a = re.captures(text).map(|c| {
				c.iter()
					.map(|m| m.map(|m| (m.start(), m.end())))
					.collect::<Vec<_>>()
			});
			let b = direct.captures(text).map(|c| {
				c.iter()
					.map(|m| m.map(|m| (m.start(), m.end())))
					.collect::<Vec<_>>()
			});
			assert_eq!(a, b);
			assert_eq!(re.replace(text, "[$word]"), direct.replace(text, "[$word]"));
			assert_eq!(re.replace_all(text, "x"), direct.replace_all(text, "x"));
			assert_eq!(re.shortest_match(text), direct.shortest_match(text));
			assert_eq!(re.captures_len(), direct.captures_len());
			assert_eq!(format!("{re:?}"), format!("{direct:?}"));
			assert_eq!(format!("{re}"), format!("{direct}"));
			assert_eq!(re.as_str(), pattern);
		}
	}
	let cache = Arc::new(Mutex::new(RegexCache::new(2)));
	let mut builder = CachedRegexBuilder::new(cache.clone(), " (?P<word> [a-z]+) ");
	builder.ignore_whitespace(true).case_insensitive(true);
	let re = builder.build().unwrap();
	assert!(re.is_match("HELLO"));
	// The upstream cache is keyed by source, so a hit retains its original options.
	let same_source = CachedRegex::new(cache, " (?P<word> [a-z]+) ").unwrap();
	assert!(same_source.is_match("HELLO"));
	let text = String::from("a123");
	let capture = {
		let cache = Arc::new(Mutex::new(RegexCache::new(2)));
		let re = CachedRegex::new(cache, r"(?P<n>\d+)").unwrap();
		re.captures(&text).unwrap()
	};
	assert_eq!(&capture["n"], "123");
}

#[test]
fn cached_hits_preserve_capacity_and_lru_order() {
	for cap in [1usize, 2, 100] {
		let cache = Arc::new(Mutex::new(RegexCache::new(cap)));
		let mut expected = Vec::<String>::new();
		let mut seed = 17u64;
		for _ in 0..1500 {
			seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
			let id = (seed >> 32) as usize % (cap + 7);
			let key = format!("^item{id}$");
			let re = CachedRegex::new(cache.clone(), &key).unwrap();
			assert!(re.is_match(&format!("item{id}")));
			if let Some(pos) = expected.iter().position(|v| v == &key) {
				expected.remove(pos);
			}
			expected.push(key);
			if expected.len() > cap {
				expected.remove(0);
			}
			let actual = cache.lock().unwrap();
			assert!(actual.len() <= cap);
			assert_eq!(
				actual.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
				expected
			);
		}
	}
}

#[test]
fn errors_and_panics_preserve_cache_state() {
	let mut cache = RegexCache::new(2);
	cache.compile("valid").unwrap();
	assert!(cache.compile("[").is_err());
	assert_eq!(cache.len(), 1);
	assert!(cache.configure("a+", |b| b.size_limit(0)).is_err());
	assert_eq!(cache.len(), 1);
	let cache = Arc::new(Mutex::new(RegexCache::new(2)));
	assert!(CachedRegex::new(cache, "[").is_err());

	// A failed lazy compilation must neither evict the existing entry nor hide the panic.
	let cache = Arc::new(Mutex::new(RegexCache::new(1)));
	cache.lock().unwrap().compile("valid").unwrap();
	let mut builder = CachedRegexBuilder::new(cache.clone(), "a+");
	builder.size_limit(0);
	let re = builder.build().unwrap();
	assert!(std::thread::spawn(move || re.is_match("aaa"))
		.join()
		.is_err());
	let poisoned = cache.lock().unwrap_err().into_inner();
	assert_eq!(poisoned.len(), 1);
	assert_eq!(poisoned.iter().next().unwrap().0, "valid");

	let zero = Arc::new(Mutex::new(RegexCache::new(0)));
	let re = CachedRegex::new(zero.clone(), "x").unwrap();
	assert!(std::thread::spawn(move || re.is_match("x")).join().is_err());
	assert!(zero.is_poisoned());
	let cache = Arc::new(Mutex::new(RegexCache::new(2)));
	let re = CachedRegex::new(cache.clone(), "x").unwrap();
	assert!(std::thread::spawn(
		move || re.replace_all("x", |_: &regex::Captures<'_>| -> String {
			panic!("replacement panic fixture")
		})
	)
	.join()
	.is_err());
	assert!(cache.is_poisoned());
}

#[test]
fn concurrent_matches_survive_cache_eviction() {
	let cache = Arc::new(Mutex::new(RegexCache::new(100)));
	std::thread::scope(|s| {
		let threads: Vec<_> = (0..8)
			.map(|thread| {
				let cache = cache.clone();
				s.spawn(move || {
					for i in 0..400 {
						let id = (i + thread * 13) % 137;
						let pattern = format!("^item{id}:(?P<n>\\d+)$");
						let re = CachedRegex::new(cache.clone(), &pattern).unwrap();
						let text = format!("item{id}:99");
						let captures = re.captures(&text).unwrap();
						assert_eq!(&captures["n"], "99");
						assert_eq!(re.replace_all(&text, "ok"), "ok");
						assert!(cache.lock().unwrap().len() <= 100);
					}
				})
			})
			.collect();
		for thread in threads {
			thread.join().unwrap();
		}
	});
}
