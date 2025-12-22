use anyhow::{
    Context,
    anyhow,
};
use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};
use sqlx::{
    Pool,
    Sqlite,
    prelude::FromRow,
};

pub async fn write_db(
    sql_pool: Pool<Sqlite>,
    message_text: String,
    date: DateTime<Utc>,
    person_from: u8,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO message(text,data,partner)")
        .bind(message_text)
        .bind(date)
        .bind(person_from)
        .execute(&sql_pool)
        .await
        .map(|_| ())
        .map_err(|_| anyhow!("Sqlite Problem"))
}
pub async fn read_db_user_message(
    sql_pool: Pool<Sqlite>,
    id: u64,
) -> anyhow::Result<Vec<(String, DateTime<Utc>, u8)>> {
    todo!()
}
pub async fn user_length(sql_pool: Pool<Sqlite>) -> anyhow::Result<u64> {
    let output: u64 = sqlx::query_scalar("SELECT COUNT(*) FROM message")
        .fetch_one(&sql_pool)
        .await
        .context("Db check Error")?;
    Ok(output)
}
pub async fn read_all_user(sql_pool: Pool<Sqlite>) -> anyhow::Result<Vec<Message>> {
    let user = sqlx::query_as::<_, Message>("SELECT text,date,partner FROM message")
        .fetch_all(&sql_pool)
        .await
        .context("Db reading of all user failed")?;
    Ok(user)
}
#[derive(Debug, FromRow, Clone)]
pub struct Message {
    pub message: String,
    pub date: DateTime<Utc>,
    pub person: u8,
}
