//! Direct SQLite connection safeguards for Linux offline Clients.
//! This module does not start Server runtimes, open pools, initialize product
//! DDL, provide administrator endpoints or select product upgrade policy.

use crate::schema_identity::{
    schema_fingerprint as fingerprint_rows, schema_identity_from_metadata_rows,
    validate_product_metadata_columns, validate_product_metadata_ddl,
};
use sqlx::{Executor, Row, Sqlite, SqliteConnection};
use thiserror::Error;

mod blocking;
pub use blocking::block_on_sqlite_connection;
mod native_limits;
pub use native_limits::{
    ConnectionLimitError, ConnectionLimits, EffectiveConnectionLimits, apply_connection_limits,
};
mod native_security;
pub use crate::schema_identity::{
    Error as SchemaIdentityError, ProductMetadataColumn, ProductMetadataRow, SchemaIdentity,
    SchemaRow,
};
pub use native_security::{ConnectionSecurityError, enable_defensive};
pub const MAX_SCHEMA_OBJECTS: usize = 1024;
pub const MAX_SCHEMA_BYTES: usize = 4 * 1024 * 1024;

pub async fn schema_rows<'executor, E>(executor: E) -> Result<Vec<SchemaRow>, Error>
where
    E: Executor<'executor, Database = Sqlite>,
{
    // Keep the version-1 filter, raw SQL bytes and BINARY ordering unchanged.
    // LIMIT 1025 proves an object excess without transferring an unbounded
    // result; window totals gate every text field before SQLx allocates it.
    let rows = sqlx::query(
        "WITH bounded AS (\
           SELECT type, name, tbl_name, COALESCE(sql, '') AS sql \
           FROM sqlite_schema \
           WHERE name NOT GLOB 'sqlite_*' AND name <> 'product_metadata' \
           ORDER BY type, name, tbl_name LIMIT 1025\
         ), charged AS (\
           SELECT *, COUNT(*) OVER () AS object_count, \
             SUM(length(CAST(type AS BLOB)) + length(CAST(name AS BLOB)) + \
                 length(CAST(tbl_name AS BLOB)) + length(CAST(sql AS BLOB))) \
               OVER () AS total_bytes FROM bounded\
         ) SELECT \
           CASE WHEN object_count <= 1024 AND total_bytes <= 4194304 THEN type END, \
           CASE WHEN object_count <= 1024 AND total_bytes <= 4194304 THEN name END, \
           CASE WHEN object_count <= 1024 AND total_bytes <= 4194304 THEN tbl_name END, \
           CASE WHEN object_count <= 1024 AND total_bytes <= 4194304 THEN sql END, \
           object_count, total_bytes FROM charged ORDER BY type, name, tbl_name",
    )
    .fetch_all(executor)
    .await?;
    if let Some(row) = rows.first()
        && (row.try_get::<i64, _>(4)? > MAX_SCHEMA_OBJECTS as i64
            || row.try_get::<i64, _>(5)? > MAX_SCHEMA_BYTES as i64)
    {
        return Err(Error::SchemaBudgetExceeded);
    }
    let rows = rows
        .into_iter()
        .map(|row| {
            Ok(SchemaRow::new(
                row.try_get::<String, _>(0)?,
                row.try_get::<String, _>(1)?,
                row.try_get::<String, _>(2)?,
                row.try_get::<String, _>(3)?,
            ))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(rows)
}

/// Calculate the canonical schema fingerprint using an arbitrary SQLx SQLite
/// executor. The pure algorithm lives in `xcsc::schema_identity`.
pub async fn schema_fingerprint<'executor, E>(executor: E) -> Result<String, Error>
where
    E: Executor<'executor, Database = Sqlite>,
{
    Ok(fingerprint_rows(&schema_rows(executor).await?)?)
}

/// Validate the metadata table and return an identity only after its declared
/// fingerprint has been verified against the actual schema.
pub async fn read_schema_identity(
    connection: &mut SqliteConnection,
) -> Result<SchemaIdentity, Error> {
    validate_metadata_table(connection).await?;
    let metadata_rows = read_metadata_rows(connection).await?;
    let identity = schema_identity_from_metadata_rows(&metadata_rows)?;
    let actual_fingerprint = schema_fingerprint(&mut *connection).await?;
    identity.verify_fingerprint(&actual_fingerprint)?;
    Ok(identity)
}

/// Validate an identity against exact compiled current values.
pub async fn require_current_schema(
    connection: &mut SqliteConnection,
    expected: &SchemaIdentity,
) -> Result<SchemaIdentity, Error> {
    let actual = read_schema_identity(connection).await?;
    actual.require_exact(expected)?;
    Ok(actual)
}

async fn validate_metadata_table(connection: &mut SqliteConnection) -> Result<(), Error> {
    let ddl: Option<String> = sqlx::query_scalar(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='product_metadata'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let ddl = ddl.ok_or(Error::ProductMetadataTableMissing)?;
    validate_product_metadata_ddl(&ddl)?;

    let columns = sqlx::query(
        "SELECT cid, name, type, \"notnull\", dflt_value, pk \
         FROM pragma_table_info('product_metadata') ORDER BY cid",
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|row| {
        Ok(ProductMetadataColumn {
            cid: row.try_get(0)?,
            name: row.try_get(1)?,
            declared_type: row.try_get(2)?,
            not_null: row.try_get(3)?,
            default_sql: row.try_get(4)?,
            primary_key_position: row.try_get(5)?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
    validate_product_metadata_columns(&columns)?;
    Ok(())
}

async fn read_metadata_rows(
    connection: &mut SqliteConnection,
) -> Result<Vec<ProductMetadataRow>, Error> {
    let rows = sqlx::query(
        "SELECT typeof(singleton), singleton, typeof(application), application, \
                typeof(application_version), application_version, \
                typeof(schema_revision), schema_revision, \
                typeof(schema_sha256), schema_sha256 \
         FROM product_metadata ORDER BY singleton LIMIT 2",
    )
    .fetch_all(connection)
    .await?;

    let mut metadata = Vec::with_capacity(rows.len());
    for row in rows {
        for (field, index, expected) in [
            ("singleton", 0, "integer"),
            ("application", 2, "text"),
            ("application_version", 4, "text"),
            ("schema_revision", 6, "integer"),
            ("schema_sha256", 8, "text"),
        ] {
            let actual: String = row.try_get(index)?;
            if actual != expected {
                return Err(Error::ProductMetadataStorageClass {
                    field,
                    expected,
                    actual,
                });
            }
        }
        metadata.push(ProductMetadataRow {
            singleton: row.try_get(1)?,
            application: row.try_get(3)?,
            application_version: row.try_get(5)?,
            schema_revision: row.try_get(7)?,
            schema_sha256: row.try_get(9)?,
        });
    }
    Ok(metadata)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("SQLite operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("database has no product_metadata table")]
    ProductMetadataTableMissing,
    #[error("SQLite schema exceeds the supported object or byte budget")]
    SchemaBudgetExceeded,
    #[error("product_metadata {field} must use SQLite storage class {expected}, found {actual}")]
    ProductMetadataStorageClass {
        field: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error(transparent)]
    SchemaIdentity(#[from] SchemaIdentityError),
}

#[cfg(test)]
mod tests;
