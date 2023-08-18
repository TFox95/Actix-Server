use actix_web::{web::Json as webJson, HttpRequest};

use sqlx::{Pool, Sqlite};

use std::error::Error;
use std::result::Result;

use super::schemas::{UserBaseSchema, RefreshTokenSchema};
use super::{
    crud::UserCRUD, schemas::AccessTokenSchema, schemas::TokenEncoded, schemas::UserLoginSchema,
};
use crate::database::models::{DatabaseTraits, SqliteStruct};

pub async fn get_db_pool(sqlite_tuple: (&str, &str, i32)) -> Result<Pool<Sqlite>, Box<dyn Error>> {
    let pool = SqliteStruct::new(sqlite_tuple.0, sqlite_tuple.1, sqlite_tuple.2)
        .establish_pool_connection_or_create()
        .await?;
    return Ok(pool);
}

pub async fn get_user(
    request: webJson<UserLoginSchema>,
    sqlite_pool: (&str, &str, i32),
) -> Result<UserBaseSchema, Box<dyn Error>> {
    let pool = get_db_pool(sqlite_pool).await?;
    let user = UserCRUD;
    let result = user
        .retrieve_user_by_username_or_email(&pool, request.username.to_string())
        .await?;

    return Ok(result);
}

pub async fn check_auth_header(
    request: HttpRequest,
    name: &str,
) -> Result<AccessTokenSchema, actix_web::Error> {

        // Extract the "Authorization" header value
        let auth_header = request
            .headers()
            .get(name)
            .ok_or_else(|| -> actix_web::Error {
                // Return an error if the header is missing
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "message" => "Missing Authorization Header"
                    }
                };
                actix_web::error::ErrorUnauthorized(jsonable.dump())
            })?;

        // Split the header value into parts
        let auth_parts: Vec<&str> = auth_header
            .to_str()
            .map_err(|_| -> actix_web::Error {
                // Return an error if the header value can't be converted to a string
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "message" => "Authorization token not found"
                    }
                };

                actix_web::error::ErrorBadRequest(jsonable.dump())
            })?
            .split("=")
            .collect();

        // Find the part that matches the specified name
        let token = TokenEncoded {
            token_key: auth_parts[1].to_owned(),
        };

        let decoded_it = match AccessTokenSchema::decode_access_token(token).await {
            Ok(result) => result,
            Err(err) => {
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "message" => err.to_string()
                    }
                };

                return Err(actix_web::error::ErrorUnauthorized(jsonable.dump()));
            }
        };
        Ok(decoded_it) 
}

pub async fn check_auth_cookies(request: HttpRequest, name: &str) -> Result<RefreshTokenSchema, actix_web::Error> {
    let auth_cookie = request.cookie(name).ok_or_else(|| -> actix_web::Error {
        let jsonable = json::object! {
            "detail" => json::object! {
                "message" => "Authorization Cookie not found.",
                "status" => 400
            }
        };

        return actix_web::error::ErrorBadRequest(jsonable.dump())
    })?;

        let jwt_token = auth_cookie.value().split("=").collect::<Vec<&str>>()[1];

        let token = TokenEncoded {
            token_key: jwt_token.to_string(),
        };

        let decoded_it = match RefreshTokenSchema::decode_access_token(token).await {
            Ok(result) => result,
            Err(_err) => {
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "message" => "Session Expired; Please log in",
                        "status_code" => 400
                    }
                };

                return Err(actix_web::error::ErrorBadRequest(jsonable.dump()));
            }
        };
        return Ok(decoded_it) 
}

pub async fn check_currently_active(request: HttpRequest, name: &str) -> Result<(), actix_web::Error> {
    
    if let Some(_) = request.headers().get(name) {
        // Return an "already logged in" response
        let jsonable = json::object! {
            "detail" => json::object! {
                "message" => "User is already logged in."
            }
        };
        return Err(actix_web::error::ErrorBadRequest(jsonable.dump()));
    }
    return Ok(())
}
