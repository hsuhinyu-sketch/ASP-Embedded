//! Offline evaluator for the real PII engine. Input/output JSONL may contain sensitive text.
use std::io::{self, BufRead, Write};
use std::time::Instant;

use security_pii::PiiConfig;
use serde::Deserialize;

#[derive(Deserialize)]
struct Input {
	id: String,
	text: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let config: PiiConfig = serde_json::from_str("{}")?;
	let engine = config.build()?.ok_or("PII engine disabled")?;
	let stdout = io::stdout();
	let mut output = io::BufWriter::new(stdout.lock());
	for line in io::stdin().lock().lines() {
		let input: Input = serde_json::from_str(&line?)?;
		let start = Instant::now();
		let result = engine.inspect(&input.text).await;
		let elapsed_ns = start.elapsed().as_nanos();
		let value = match result {
			Ok(outcome) => serde_json::json!({
				"id": input.id, "text": outcome.text, "findings": outcome.findings,
				"blocked": outcome.blocked, "elapsedNs": elapsed_ns,
			}),
			Err(error) => serde_json::json!({
				"id": input.id, "error": error.to_string(), "elapsedNs": elapsed_ns,
			}),
		};
		serde_json::to_writer(&mut output, &value)?;
		writeln!(output)?;
	}
	output.flush()?;
	Ok(())
}
