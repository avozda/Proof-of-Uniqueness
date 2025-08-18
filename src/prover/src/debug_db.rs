use num_bigint::BigUint;
use rocksdb::{DB, IteratorMode, Options};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Debug utility to dump our custom SMT database content to JSON
pub fn dump_db_to_json<P: AsRef<Path>>(
    db_path: P,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path.as_ref();

    if !path.exists() {
        println!("❌ Database path does not exist: {:?}", path);
        return Ok(());
    }

    println!("🔍 Dumping custom 254-bit SMT database content...");

    // Open the RocksDB database
    let mut opts = Options::default();
    opts.create_if_missing(false); // Don't create, just read
    let db = DB::open_for_read_only(&opts, path, false)?;

    let mut content = HashMap::new();
    let mut stats = HashMap::new();
    let mut leaf_count = 0;
    let mut node_count = 0;
    let mut other_count = 0;

    // Iterate through all key-value pairs
    let iter = db.iterator(IteratorMode::Start);
    for item in iter {
        let (key, value) = item?;
        let key_str = hex::encode(&key);
        let key_utf8 = String::from_utf8_lossy(&key);

        // Categorize the entries
        if key_str == hex::encode(b"_______monotree::headroot_______") {
            // This is the root key
            let root_value = BigUint::from_bytes_be(&value);
            content.insert(
                "root".to_string(),
                json!({
                    "type": "root",
                    "key_hex": key_str,
                    "value_hex": hex::encode(&value),
                    "value_bigint": root_value.to_string(),
                    "description": "Current SMT root hash"
                }),
            );
        } else if key_utf8.starts_with("leaf_") {
            // This is a leaf entry (our hash_id storage)
            let hash_id = key_utf8.strip_prefix("leaf_").unwrap_or("unknown");
            let value_bigint = BigUint::from_bytes_be(&value);
            content.insert(
                format!("leaf_{}", leaf_count),
                json!({
                    "type": "leaf",
                    "key_hex": key_str,
                    "key_utf8": key_utf8,
                    "hash_id": hash_id,
                    "value_hex": hex::encode(&value),
                    "value_bigint": value_bigint.to_string(),
                    "description": "Inserted hash_id value"
                }),
            );
            leaf_count += 1;
        } else if value.len() > 32 {
            // This might be a serialized node
            content.insert(
                format!("node_{}", node_count),
                json!({
                    "type": "node",
                    "key_hex": key_str,
                    "value_hex": hex::encode(&value),
                    "value_length": value.len(),
                    "description": "SMT internal node"
                }),
            );
            node_count += 1;
        } else {
            // Other entries
            let value_bigint = BigUint::from_bytes_be(&value);
            content.insert(
                format!("other_{}", other_count),
                json!({
                    "type": "other",
                    "key_hex": key_str,
                    "key_utf8": key_utf8,
                    "value_hex": hex::encode(&value),
                    "value_bigint": value_bigint.to_string(),
                    "description": "Other database entry"
                }),
            );
            other_count += 1;
        }
    }

    // Add statistics
    stats.insert(
        "total_entries",
        json!(
            leaf_count
                + node_count
                + other_count
                + if content.contains_key("root") { 1 } else { 0 }
        ),
    );
    stats.insert("leaf_entries", json!(leaf_count));
    stats.insert("node_entries", json!(node_count));
    stats.insert("other_entries", json!(other_count));
    stats.insert("has_root", json!(content.contains_key("root")));

    let output = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "database_path": path.to_string_lossy(),
        "smt_type": "Custom 254-bit SMT with RocksDB",
        "statistics": stats,
        "content": content
    });

    fs::write(output_file, serde_json::to_string_pretty(&output)?)?;
    println!("✅ Database content written to: {}", output_file);
    println!(
        "📊 Found {} total entries ({} leaves, {} nodes, {} other)",
        stats["total_entries"], leaf_count, node_count, other_count
    );

    Ok(())
}

/// Pretty print database content for console debugging
pub fn print_db_summary<P: AsRef<Path>>(db_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let path = db_path.as_ref();

    if !path.exists() {
        println!("❌ Database path does not exist: {:?}", path);
        return Ok(());
    }

    println!("\n🔍 Custom 254-bit SMT Database Summary");
    println!("📁 Path: {:?}", path);
    println!("{}", "=".repeat(60));

    // Open the RocksDB database
    let mut opts = Options::default();
    opts.create_if_missing(false);
    let db = DB::open_for_read_only(&opts, path, false)?;

    let mut leaf_count = 0;
    let mut node_count = 0;
    let mut other_count = 0;
    let mut current_root: Option<BigUint> = None;

    // Iterate and analyze
    let iter = db.iterator(IteratorMode::Start);
    for item in iter {
        let (key, value) = item?;
        let key_str = String::from_utf8_lossy(&key);

        if hex::encode(&key) == hex::encode(b"_______monotree::headroot_______") {
            current_root = Some(BigUint::from_bytes_be(&value));
        } else if key_str.starts_with("leaf_") {
            leaf_count += 1;
        } else if value.len() > 32 {
            node_count += 1;
        } else {
            other_count += 1;
        }
    }

    println!(
        "🌳 SMT Root: {}",
        current_root
            .as_ref()
            .map_or("None (empty)".to_string(), |r| r.to_string())
    );
    println!("📊 Database Statistics:");
    println!("   📄 Leaf entries (hash_ids): {}", leaf_count);
    println!("   🌿 Internal nodes: {}", node_count);
    println!("   📦 Other entries: {}", other_count);
    println!(
        "   📈 Total entries: {}",
        leaf_count + node_count + other_count + if current_root.is_some() { 1 } else { 0 }
    );

    if leaf_count > 0 {
        println!("\n📋 Sample Leaf Entries:");
        let iter = db.iterator(IteratorMode::Start);
        let mut shown = 0;
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8_lossy(&key);
            if key_str.starts_with("leaf_") && shown < 3 {
                let hash_id = key_str.strip_prefix("leaf_").unwrap_or("unknown");
                let value_bigint = BigUint::from_bytes_be(&value);
                println!("   🔑 Hash ID: {}", hash_id);
                println!("      💎 Value: {}", value_bigint);
                shown += 1;
            }
        }
        if leaf_count > 3 {
            println!("   ... and {} more entries", leaf_count - 3);
        }
    }

    println!("{}", "=".repeat(60));
    println!("📝 Status: Ready for 254-bit SMT operations");

    Ok(())
}

/// Get the current SMT root from the database
pub fn get_current_root<P: AsRef<Path>>(
    db_path: P,
) -> Result<Option<BigUint>, Box<dyn std::error::Error>> {
    let path = db_path.as_ref();

    if !path.exists() {
        return Ok(None);
    }

    let mut opts = Options::default();
    opts.create_if_missing(false);
    let db = DB::open_for_read_only(&opts, path, false)?;

    match db.get(b"_______monotree::headroot_______")? {
        Some(root_bytes) => Ok(Some(BigUint::from_bytes_be(&root_bytes))),
        None => Ok(None),
    }
}

/// Check if a specific hash_id exists in the database
pub fn check_hash_id_exists<P: AsRef<Path>>(
    db_path: P,
    hash_id: &BigUint,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path = db_path.as_ref();

    if !path.exists() {
        return Ok(false);
    }

    let mut opts = Options::default();
    opts.create_if_missing(false);
    let db = DB::open_for_read_only(&opts, path, false)?;

    let leaf_key = format!("leaf_{}", hash_id);
    Ok(db.get(leaf_key.as_bytes())?.is_some())
}
