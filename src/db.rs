use anyhow::{
    Context,
    anyhow,
};
use chrono::{
    DateTime,
    Utc,
};
use sqlx::{
    Pool,
    Sqlite,
};

use crate::interface::Nachricht;

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
pub async fn user_length(sql_pool: Pool<Sqlite>) -> anyhow::Result<u64> {
    let output: u64 = sqlx::query_scalar("SELECT COUNT(*) FROM message")
        .fetch_one(&sql_pool)
        .await
        .context("Db check Error")?;
    Ok(output)
}
pub async fn read_all_user(sql_pool: Pool<Sqlite>) -> anyhow::Result<Vec<Nachricht>> {
    let user = sqlx::query_as::<_, Nachricht>("SELECT * FROM message")
        .fetch_all(&sql_pool)
        .await
        .context("Db reading of all user failed")?;
    Ok(user)
}
