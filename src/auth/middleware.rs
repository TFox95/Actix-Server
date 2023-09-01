use actix_web::{web::Json as webJson, HttpRequest};

use sqlx::{Pool, Sqlite};

use std::error::Error;
use std::result::Result;

use super::schemas::{UserBaseSchema, RefreshTokenSchema};
use super::{
    crud::AuthHandler,
    crud::UserCRUD, 
    schemas::AccessTokenSchema, 
    schemas::TokenEncoded, 
    schemas::UserLoginSchema,
};
use crate::database::models::{
    DatabaseTraits, 
    SqliteStruct
};

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
    let result: Result<UserBaseSchema, Box<dyn Error>> = user.retrieve_user(&pool, request.username.to_string()).await;

    match result {
        Ok(user) => {
            let password_check = AuthHandler.verify_password( &user.password, &AuthHandler.get_password_hash(&request.password));
            if !password_check {
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "status_code" => 400,
                        "message" => "Username or Password was incorrect; Please try again."
                    }
                };
                let error_response = actix_web::error::ErrorBadRequest(jsonable.dump());
                return Err(Box::new(error_response))
            };
            return Ok(user) 
        },
        Err(_) => {
            let jsonable = json::object! {
                "detail" => json::object! {
                    "status_code" => 404,
                    "message" => "Wasn't able to locate your account, please try again"
                }
            };
        let error_response = actix_web::error::ErrorNotFound(jsonable.dump());
        return Err(Box::new(error_response));

        }
    }
}

pub async fn check_headers(
    request: HttpRequest,
    name: &str,
) -> Result<AccessTokenSchema, actix_web::Error> {
    
    if name == "Authorization" {
        check_cookies(request.clone(), name).await?;
    };
         // Extract the "Authorization" header value
    let auth_header = request
        .headers()
        .get(name)
        .ok_or_else(|| -> actix_web::Error {
            // Return an error if the header is missing
            let jsonable = json::object! {
                "detail" => json::object! {
                    "message" => format!("Missing {} Header", name)
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
                        "message" => format!("{} key not found", name)
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

        match AccessTokenSchema::decode_access_token(token).await {
            Ok(result) =>  return Ok(result),
            Err(err) => {
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "message" => err.to_string()
                    }
                };

                return Err(actix_web::error::ErrorUnauthorized(jsonable.dump()));
            }
        }; 
}

pub async fn check_cookies(request: HttpRequest, name: &str) -> Result<RefreshTokenSchema, actix_web::Error> {
    let auth_cookie = request.cookie(name).ok_or_else(|| -> actix_web::Error {
        let jsonable = json::object! {
            "detail" => json::object! {
                "message" => format!("{} Cookie not found.", name),
                "status" => 400
            }
        };

        return actix_web::error::ErrorBadRequest(jsonable.dump())
    })?;

    if auth_cookie.value().is_empty() {
        let jsonable = json::object! {
            "detail" => json::object! {
                "message" => "Session Expired; Please log in",
                "status_code" => 400
            }
        };

        return Err(actix_web::error::ErrorBadRequest(jsonable.dump()));

    }

    let token = TokenEncoded {
        token_key: auth_cookie.value().split("=").collect::<Vec<&str>>()[1].to_string()
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
    
    if let Some(val) = request.headers().get(name) {
        // Return an "already logged in" response
        if val.to_str().unwrap() == "" {
            return Ok(())
        }
        let jsonable = json::object! {
            "detail" => json::object! {
                "message" => "User is already logged in."
            }
        };
        return Err(actix_web::error::ErrorBadRequest(jsonable.dump()));
    }
    return Ok(())
}
