use std::path::PathBuf;

use crate::MigrateArgs;

pub(crate) fn execute(args: MigrateArgs) -> anyhow::Result<()> {
	let MigrateArgs { file } = args;
	migrate_file(file)
}

fn migrate_file(path: PathBuf) -> anyhow::Result<()> {
	let contents = fs_err::read_to_string(&path)?;
	let migrated =
		ai_security_platform_runtime::types::local::migrate_deprecated_local_config(&contents)?;
	fs_err::write(&path, migrated)?;
	println!("Migrated config: {}", path.display());
	Ok(())
}

/// An administrator-owned migration declaration, not a gateway configuration or server.
#[cfg(feature = "security-rag-sqlite")]
pub(crate) fn import_rag_state(args: MigrateArgs) -> anyhow::Result<()> {
	let contents = fs_err::read_to_string(args.file)?;
	let config: security_integration_runtime::rag_sqlite::migration::ImportConfig =
		serde_yaml::from_str(&contents)?;
	let report = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()?
		.block_on(security_integration_runtime::rag_sqlite::migration::import(
			config,
		))
		.map_err(anyhow::Error::msg)?;
	println!(
		"Imported {} documents and {} unexpired Context records; source journals retained",
		report.documents, report.contexts
	);
	Ok(())
}
