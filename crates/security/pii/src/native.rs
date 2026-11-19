use crate::*;
use phonenumber::country;
use regex::Regex;
use std::net::IpAddr;

const PHONE_REGIONS: [country::Id; 7] = [
	country::CN,
	country::US,
	country::GB,
	country::DE,
	country::IN,
	country::CA,
	country::BR,
];

fn valid_phone_number(value: &str) -> bool {
	let mut rejected: [Option<phonenumber::PhoneNumber>; PHONE_REGIONS.len()] =
		std::array::from_fn(|_| None);
	for (index, region) in PHONE_REGIONS.into_iter().enumerate() {
		let Ok(number) = phonenumber::parse(Some(region), value) else {
			continue;
		};
		// Only complete, equal parsed numbers share a rejection within this candidate.
		if rejected[..index]
			.iter()
			.flatten()
			.any(|prior| prior == &number)
		{
			continue;
		}
		if number.is_valid() {
			return true;
		}
		rejected[index] = Some(number);
	}
	false
}

pub struct NativeDetector {
	rules: Vec<(String, Regex)>,
	max_bytes: usize,
	max_findings: usize,
	timeout: std::time::Duration,
}
impl NativeDetector {
	pub fn new(config: &PiiConfig) -> Result<Self, PiiError> {
		config.validate()?;
		let mut rules = Vec::new();
		for entity in config.policy.entities.keys() {
			let pattern = match entity.as_str() {
				"EMAIL_ADDRESS" => r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}",
				"PHONE_NUMBER" => {
					r"\+?[1-9][0-9]{7,14}|\+?[0-9]{1,3}[ -]?\(?[0-9]{2,4}\)?[ -]?[0-9]{3,4}[ -]?[0-9]{3,4}|\(?[0-9]{3}\)?[ -]?[0-9]{3}[ -]?[0-9]{4}"
				},
				"IP_ADDRESS" => r"[0-9A-Fa-f:.]+",
				_ => config
					.custom_rules
					.get(entity)
					.ok_or(PiiError::InvalidConfig)?,
			};
			let regex = regex::RegexBuilder::new(pattern)
				.size_limit(1_048_576)
				.dfa_size_limit(1_048_576)
				.build()
				.map_err(|_| PiiError::InvalidConfig)?;
			if regex.is_match("") {
				return Err(PiiError::InvalidConfig);
			}
			rules.push((entity.clone(), regex));
		}
		Ok(Self {
			rules,
			max_bytes: config.max_text_bytes,
			max_findings: config.max_findings,
			timeout: std::time::Duration::from_millis(config.timeout_ms),
		})
	}
}
#[async_trait::async_trait]
impl PiiDetector for NativeDetector {
	async fn prepare(&self) -> Result<(), PiiError> {
		if !self
			.rules
			.iter()
			.any(|(entity, _)| entity == "PHONE_NUMBER")
		{
			return Ok(());
		}
		tokio::task::spawn_blocking(|| {
			// Initialize the shared metadata, a valid local sample, and regional rejection paths.
			// Synthetic values stay local; their validity is not a policy decision.
			let _ = phonenumber::parse(Some(country::CN), "13800138000").is_ok_and(|n| n.is_valid());
			for region in PHONE_REGIONS {
				let _ = phonenumber::parse(Some(region), "1111111111").is_ok_and(|n| n.is_valid());
			}
		})
		.await
		.map_err(|_| PiiError::Unavailable)
	}

	async fn detect(&self, text: &str, _language: &str) -> Result<Vec<PiiFinding>, PiiError> {
		if text.len() > self.max_bytes {
			return Err(PiiError::InputLimit);
		}
		let deadline = tokio::time::Instant::now() + self.timeout;
		let mut output = Vec::new();
		for (entity, regex) in &self.rules {
			for (index, item) in regex.find_iter(text).enumerate() {
				// Bound time spent on rejected candidates too. Individual regex searches and
				// phone parses are synchronous; cancellation resumes at these checkpoints.
				if index != 0 && index % 32 == 0 {
					tokio::task::yield_now().await;
				}
				if tokio::time::Instant::now() >= deadline {
					return Err(PiiError::Timeout);
				}
				let value = if entity == "IP_ADDRESS" && item.as_str().parse::<IpAddr>().is_err() {
					item.as_str().trim_end_matches('.')
				} else {
					item.as_str()
				};
				let end = item.start() + value.len();
				let bounded = text[..item.start()]
					.chars()
					.next_back()
					.is_none_or(|c| !c.is_ascii_alphanumeric() && c != b'_' as char)
					&& text[end..]
						.chars()
						.next()
						.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
				let valid = match entity.as_str() {
					"EMAIL_ADDRESS" => {
						bounded
							&& !value.starts_with('.')
							&& !value.contains("..")
							&& !value
								.split('@')
								.nth(1)
								.unwrap_or("")
								.split('.')
								.any(|part| part.starts_with('-') || part.ends_with('-'))
					},
					"IP_ADDRESS" => bounded && value.parse::<IpAddr>().is_ok(),
					"PHONE_NUMBER" => {
						let digits = value.bytes().filter(u8::is_ascii_digit).count();
						bounded
							&& (8..=15).contains(&digits)
							&& value.parse::<IpAddr>().is_err()
							&& valid_phone_number(value)
					},
					_ => true,
				};
				if tokio::time::Instant::now() >= deadline {
					return Err(PiiError::Timeout);
				}
				if !valid {
					continue;
				}
				if output.len() == self.max_findings {
					return Err(PiiError::FindingLimit);
				}
				output.push(PiiFinding {
					entity_type: entity.clone(),
					start: item.start(),
					end,
					confidence: 0.8,
					source: "native".into(),
				});
			}
			if tokio::time::Instant::now() >= deadline {
				return Err(PiiError::Timeout);
			}
		}
		Ok(output)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn candidate_reuse_matches_independent_regional_validation() {
		let reference = |value: &str| {
			PHONE_REGIONS
				.into_iter()
				.any(|region| phonenumber::parse(Some(region), value).is_ok_and(|n| n.is_valid()))
		};
		for value in [
			"",
			"1111111111",
			"13800138000",
			"+86 138 0013 8000",
			"+1 202-555-0123",
			"+1 647-555-0123",
			"+44 20 7946 0958",
			"+49 30 901820",
			"+91 98765 43210",
			"+55 11 91234-5678",
			"+39 02 36618 300",
			"+1 202-555-0123 ext. 001",
			"+1 202-555-0123 ext. 002",
			"020 7946 0958",
			"0044 20 7946 0958",
			"192.0.2.1",
			"not a phone",
		] {
			assert_eq!(valid_phone_number(value), reference(value), "{value}");
		}
		for digits in 8..=15 {
			for index in 0..512u64 {
				let number = 10u64.pow(digits - 1) + index * 104729;
				for value in [number.to_string(), format!("+{number}")] {
					assert_eq!(valid_phone_number(&value), reference(&value), "{value}");
				}
			}
		}
	}
}
