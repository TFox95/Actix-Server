use async_trait_fn::async_trait;

use std::error::Error;
use std::result::Result;

pub struct SqliteStruct<'a> {
    pub connection: &'a str,
    pub connection_type: &'a str,
    pub total_connections: i32,
}

#[async_trait]
pub trait DatabaseTraits {
    async fn establish_pool_connection_or_create(
        &self,
    ) -> Result<sqlx::Pool<sqlx::Sqlite>, Box<dyn Error>>;

    async fn establish_single_connection_or_create(
        &self,
    ) -> Result<sqlx::SqliteConnection, Box<dyn Error>>;

    fn new<'a>(
        connection: &'a str,
        connection_type: &'a str,
        total_connections: i32,
    ) -> SqliteStruct<'a> {
        return SqliteStruct {
            connection,
            connection_type,
            total_connections,
        };
    }
}
