//! Synchronous entry point for the SQLite driver's connection worker.

use std::future::Future;

/// Complete a trusted direct [`sqlx::SqliteConnection`] operation synchronously.
///
/// SQLite connection creation, statements and explicit connection closure use
/// SQLx's native worker thread and channels. They do not require a Tokio reactor.
/// This entry point also works inside a Tokio current-thread or multi-thread
/// runtime without starting a nested Tokio runtime.
///
/// The future must contain only direct SQLite connection work. Pools, Tokio
/// timers/network/filesystem futures and recursively calling this function are
/// outside this contract. The caller must explicitly close every connection
/// before completing its future; this function does not replace that ownership.
pub fn block_on_sqlite_connection<F: Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{
        Connection, SqliteConnection, sqlite::SqliteConnectOptions, sqlite::SqliteJournalMode,
    };
    use std::{fs, path::Path, time::Duration};

    fn exercise_direct_connection(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        block_on_sqlite_connection(async {
            let mut connection = SqliteConnection::connect_with(
                &SqliteConnectOptions::new()
                    .filename(path)
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal),
            )
            .await?;
            sqlx::raw_sql("CREATE TABLE items(value INTEGER NOT NULL);INSERT INTO items VALUES(7)")
                .execute(&mut connection)
                .await?;
            let value: i64 = sqlx::query_scalar("SELECT value FROM items")
                .fetch_one(&mut connection)
                .await?;
            assert_eq!(value, 7);
            // Closing the native worker, rather than dropping a pool, is the
            // required boundary before byte snapshots and permission changes.
            connection.close().await?;
            Ok::<_, sqlx::Error>(())
        })?;
        let bytes = fs::read(path)?;
        let wal = path.with_extension("sqlite3-wal");
        let shm = path.with_extension("sqlite3-shm");
        assert!(!wal.exists());
        assert!(!shm.exists());
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(fs::read(path)?, bytes);
        assert!(!wal.exists());
        assert!(!shm.exists());
        Ok(())
    }

    #[test]
    fn direct_connection_without_an_async_runtime_closes_before_returning()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        exercise_direct_connection(&directory.path().join("outside.sqlite3"))
    }

    #[test]
    fn direct_connection_inside_current_thread_runtime_closes_before_returning()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(async {
                exercise_direct_connection(&directory.path().join("current.sqlite3"))
            })
    }

    #[test]
    fn direct_connection_inside_multi_thread_runtime_closes_before_returning()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()?
            .block_on(async { exercise_direct_connection(&directory.path().join("multi.sqlite3")) })
    }
}
