use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::{Connection, Error, Pool, Sqlite};

use async_trait_fn::async_trait;

use std::error::Error as stdError;
use std::result::Result;

use crate::database::models::DatabaseTraits;
use crate::database::models::SqliteStruct;

#[async_trait]
impl<'a> DatabaseTraits for SqliteStruct<'a> {
    async fn establish_pool_connection_or_create(&self) -> Result<Pool<Sqlite>, Box<dyn stdError>> {
        let conn_url = format!("{}{}", &self.connection, &self.connection_type);
        let pool_result = SqlitePool::connect(&conn_url).await;

        match pool_result {
            // If the connection pool is successfully established, return it
            Ok(pool) => return Ok(pool),

            Err(err) => {
                // If there was an error establishing the connection pool, give it the name db_error and
                // check if the message contained is due to a missing or unable to open database file.
                if let Error::Database(db_error) = &err {
                    if db_error.message().contains("unable to open database file") {
                        println!(
                            "Unable to access/open database. Initiating new database creation."
                        );
                        // If the error indicates that the database file is missing, create the database file
                        let connect_options = SqliteConnectOptions::new()
                            .filename(&conn_url)
                            .create_if_missing(true);

                        // Attempt to establish the connection pool again
                        let pool = SqlitePool::connect_with(connect_options).await?;

                        // Return the newly created connection pool
                        Ok(pool)
                    } else {
                        // If the error is due to some other database issue, return the original error
                        Err(Box::new(err).into())
                    }
                } else {
                    // If the error is not related to the database, return the original error
                    Err(Box::new(err).into())
                }
            }
        }
    }

    async fn establish_single_connection_or_create(
        &self,
    ) -> Result<sqlx::SqliteConnection, Box<dyn stdError>> {
        let connection = format!("{}{}", self.connection, self.connection_type);
        let mut _established = sqlx::sqlite::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&connection)
                .create_if_missing(true),
        )
        .await?;

        return Ok(_established);
    }
}
