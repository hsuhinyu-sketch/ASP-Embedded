use crate::ExportAuditArgs;

pub(crate) fn export(args: ExportAuditArgs) -> anyhow::Result<()> {
	let document =
		ai_security_platform_runtime::config::parse_document(&fs_err::read_to_string(args.file)?)?;
	let source = document
		.get("config")
		.and_then(|config| config.get("securityAudit"))
		.ok_or_else(|| anyhow::anyhow!("export-audit requires config.securityAudit"))?;
	let source = serde_json::from_value::<security_audit::AuditJournalConfig>(source.clone())?;
	let report =
		security_audit::RotatingAuditJournal::<serde_json::Value>::export(source, &args.output)?;
	println!(
		"Exported {} audit files through sequence {}; source evidence retained",
		report.files.len(),
		report.last_sequence
	);
	Ok(())
}
