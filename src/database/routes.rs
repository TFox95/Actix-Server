use std::error::Error;

use actix_web::web::{scope, ServiceConfig};
use actix_web::{get, post, HttpResponse as Response, Responder};
use sqlx::Row;

use crate::database::models::DatabaseTraits;
use crate::database::models::SqliteStruct;

use json;

static SQLITE_TUPLE: (&str, &str, i32) = ("database", ".sqlite", 10);

#[get("/")]
async fn index() -> impl Responder {
    let data = json::object! {
        "data" => json::object! {
            "db" => "sqlite",
            "name" => "database",
            "suffix" => ".db",
            "connection" => "Established",
        }
    };
    return Response::Ok().body(data.dump());
}

#[get("/migrate")]
async fn migrated() -> Result<impl Responder, Box<dyn Error>> {
    let conn = SqliteStruct {
        connection: &SQLITE_TUPLE.0,
        connection_type: &SQLITE_TUPLE.1,
        total_connections: SQLITE_TUPLE.2.clone(),
    }
    .establish_pool_connection_or_create()
    .await?;
    println!("le go");

    sqlx::migrate!().run(&conn).await?;

    let jsonify = json::object! {
        "data" => "Migrated Successfully."
    };
    return Ok(Response::Ok().body(jsonify.dump()));
}

#[post("/reach")]
async fn reach() -> Result<impl Responder, Box<dyn Error>> {
    let mut conn = SqliteStruct {
        connection: &SQLITE_TUPLE.0,
        connection_type: &SQLITE_TUPLE.1,
        total_connections: SQLITE_TUPLE.2.clone(),
    }
    .establish_single_connection_or_create()
    .await?;

    println!("{:?}", conn);

    let res = sqlx::query("SELECT 1 + 1 as sum")
        .fetch_one(&mut conn)
        .await?;

    let sum: i32 = res.get("sum");

    println!("{}", sum);

    return Ok(Response::Ok());
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(scope("/db").service(index).service(reach).service(migrated));
}
