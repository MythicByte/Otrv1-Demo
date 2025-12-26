use anyhow::{
    Context,
    anyhow,
};
use sqlx::{
    Pool,
    Sqlite,
};

use crate::interface::Nachricht;

/// Writes a text query into the sqlite db
///
/// Needed for new Message to store
pub async fn write_db(sql_pool: Pool<Sqlite>, content: Nachricht) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO message(text,date,partner) VALUES (?,?,?)")
        .bind(content.message_text)
        .bind(content.date_of_message)
        .bind(content.person_from)
        .execute(&sql_pool)
        .await
        .map(|_| ())
        .map_err(|_| anyhow!("Sqlite Problem"))
}
/// read the [Nachricht] with the id set as minimum
///
/// Needed for loading the Scrollable content to be displayed
pub async fn read_nachricht_with_id_max(
    sql_pool: Pool<Sqlite>,
    id: i64,
) -> anyhow::Result<Vec<Nachricht>> {
    let user_with_id = sqlx::query_as::<_, Nachricht>("SELECT * FROM message WHERE id > ?")
        .bind(id)
        .fetch_all(&sql_pool)
        .await
        .context("Fetching from db failed")?;
    Ok(user_with_id)
}
#[cfg(test)]
mod tests {

    use super::*;
    use chrono::Utc;
    use sqlx::{
        Pool,
        Sqlite,
        SqlitePool,
        sqlite::SqlitePoolOptions,
    };

    #[tokio::test]
    async fn test_reading_all_user_db() {
        let pool = sql_pool().await;
        let nachricht = Nachricht::new("Alice".to_string(), Utc::now(), 0);
        let _result_write = write_db(pool.clone(), nachricht).await.unwrap();
        let result_read = read_all_user(pool.clone()).await;
        // dbg!(&result);
        assert!(result_read.is_ok());
    }
    #[tokio::test]
    async fn test_db_insert() {
        let pool = sql_pool().await;
        let nachricht = Nachricht::new("Alice".to_string(), Utc::now(), 0);
        let result = write_db(pool, nachricht).await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn test_db_id() {
        let pool = sql_pool().await;
        let nachricht = Nachricht::new("Alice".to_string(), Utc::now(), 0);
        for _ in 0..10 {
            let _result = write_db(pool.clone(), nachricht.clone()).await.unwrap();
        }
        let number = read_nachricht_with_id_max(pool.clone(), 5).await.unwrap();
        assert_eq!(number.len(), 5)
    }
    async fn sql_pool() -> SqlitePool {
        let pool = {
            let pool: Pool<Sqlite> = SqlitePoolOptions::new()
                .max_connections(4)
                .connect("sqlite::memory:")
                .await
                .expect("Sqlite Pool failed");
            sqlx::migrate!()
                .run(&pool)
                .await
                .expect("Sqlite Migrations failed");
            pool
        };
        pool
    }
    /// Read all user from the sqlite db
    async fn read_all_user(sql_pool: Pool<Sqlite>) -> anyhow::Result<Vec<Nachricht>> {
        let user = sqlx::query_as::<_, Nachricht>("SELECT * FROM message")
            .fetch_all(&sql_pool)
            .await
            .context("Db reading of all user failed")?;
        Ok(user)
    }
}
