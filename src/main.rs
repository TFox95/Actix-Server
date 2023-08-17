mod auth;
mod database;
mod utils;

use crate::auth::routes as a_routes;
use crate::database::routes as d_routes;
use crate::utils::config::get_server_time;

use dotenv::dotenv;
use env_logger::Env;
use std::env::var;

use actix_web::middleware::Logger;
use actix_web::{get, main, App, HttpResponse, HttpServer, Responder};
use json;

#[get("/")]
async fn index() -> impl Responder {
    let jsonb = json::object! {
        "data" => json::object! {
            "name" => "John Doe",
            "age" => "30",
            "email"=> "aesrdtyg@esdtf.com",
            "time" => get_server_time().unwrap().to_string()
        }
    };
    return HttpResponse::Ok().body(jsonb.dump());
}

#[main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let server_address: String = var("SERVER_ADDRESS").unwrap().to_string();
    let server_port = var("SERVER_PORT")
        .unwrap()
        .to_string()
        .parse::<u16>()
        .unwrap();

    env_logger::init_from_env(Env::default().default_filter_or("info"));
    HttpServer::new(move || {
        App::new()
            .service(index)
            .configure(d_routes::config)
            .configure(a_routes::config)
            .wrap(Logger::default())
    })
    .bind((server_address, server_port))?
    .run()
    .await
}
