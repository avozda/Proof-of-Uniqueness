//! A module for implementing RocksDB database supporting the 254-bit SMT.
use crate::smt::lib::*;
use rocksdb::{DB, Options};

/// A trait defining databases used for SMT.
pub trait Database {
    fn new(dbpath: &str) -> Self;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, key: &[u8], value: Vec<u8>) -> Result<()>;
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    fn init_batch(&mut self) -> Result<()>;
    fn write_batch(&mut self) -> Result<()>;
    fn cancel_batch(&mut self) -> Result<()>;
}

#[derive(Debug)]
/// A database using `RocksDB`
pub struct RocksDB {
    db: DB,
}

impl Database for RocksDB {
    fn new(dbpath: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let db = DB::open(&opts, dbpath).expect("Failed to open RocksDB");

        RocksDB { db }
    }

    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.db.get(key) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => Ok(None),
            Err(e) => Err(Errors::new(&format!("RocksDB get error: {}", e))),
        }
    }

    fn put(&mut self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.db
            .put(key, value)
            .map_err(|e| Errors::new(&format!("RocksDB put error: {}", e)))
    }

    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.db
            .delete(key)
            .map_err(|e| Errors::new(&format!("RocksDB delete error: {}", e)))
    }

    fn init_batch(&mut self) -> Result<()> {
        // RocksDB batch operations are different, for now just return Ok
        // This can be enhanced later with WriteBatch if needed
        Ok(())
    }

    fn write_batch(&mut self) -> Result<()> {
        // RocksDB batch operations are different, for now just return Ok
        Ok(())
    }

    fn cancel_batch(&mut self) -> Result<()> {
        // RocksDB batch operations are different, for now just return Ok
        Ok(())
    }
}
