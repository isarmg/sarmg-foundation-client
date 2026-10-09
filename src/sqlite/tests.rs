use super::*;
use sqlx::Connection;

#[tokio::test]
async fn offline_inspection_requires_exact_metadata_and_preserves_the_current_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    sqlx::raw_sql("CREATE TABLE items(value INTEGER NOT NULL);")
        .execute(&mut connection)
        .await?;
    let fingerprint = schema_fingerprint(&mut connection).await?;
    let expected = SchemaIdentity::new("sample-product", "1.0.0", 1, fingerprint.clone())?;
    sqlx::raw_sql(crate::schema_identity::PRODUCT_METADATA_DDL)
        .execute(&mut connection)
        .await?;
    sqlx::query("INSERT INTO product_metadata VALUES(1,?,?,?,?)")
        .bind(&expected.application)
        .bind(&expected.application_version)
        .bind(expected.schema_revision as i64)
        .bind(&expected.schema_sha256)
        .execute(&mut connection)
        .await?;
    apply_connection_limits(&mut connection, ConnectionLimits::new(1024 * 1024)).await?;
    enable_defensive(&mut connection).await?;
    assert_eq!(
        require_current_schema(&mut connection, &expected).await?,
        expected
    );
    assert_eq!(schema_fingerprint(&mut connection).await?, fingerprint);
    let wrong = SchemaIdentity::new("sample-product", "2.0.0", 1, fingerprint.clone())?;
    assert!(matches!(
        require_current_schema(&mut connection, &wrong).await,
        Err(Error::SchemaIdentity(
            crate::schema_identity::Error::IdentityMismatch { .. }
        ))
    ));
    sqlx::query("UPDATE product_metadata SET schema_sha256=?")
        .bind("a".repeat(64))
        .execute(&mut connection)
        .await?;
    assert!(matches!(
        read_schema_identity(&mut connection).await,
        Err(Error::SchemaIdentity(
            crate::schema_identity::Error::SchemaFingerprintMismatch { .. }
        ))
    ));
    assert_eq!(schema_fingerprint(&mut connection).await?, fingerprint);
    connection.close().await?;
    Ok(())
}

#[tokio::test]
async fn offline_inspection_rejects_missing_and_replaced_metadata_tables()
-> Result<(), Box<dyn std::error::Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;
    assert!(matches!(
        read_schema_identity(&mut connection).await,
        Err(Error::ProductMetadataTableMissing)
    ));
    sqlx::raw_sql("CREATE TABLE product_metadata(singleton INTEGER, application TEXT);")
        .execute(&mut connection)
        .await?;
    assert!(matches!(
        read_schema_identity(&mut connection).await,
        Err(Error::SchemaIdentity(
            crate::schema_identity::Error::ProductMetadataDdlMismatch
        ))
    ));
    connection.close().await?;
    Ok(())
}
