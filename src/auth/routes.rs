use actix_web::{
    cookie::time::Duration, cookie::Cookie, delete, get, post, patch, http::StatusCode, web::scope,
    web::Json as webJson, web::ServiceConfig, HttpRequest, HttpResponse as Response, Responder,
};

use std::error::Error;
use std::result::Result;

use super::{
    crud::UserCRUD,
    middleware::{
        check_cookies,
        check_currently_active,
        check_headers, 
        get_db_pool, 
        get_user
    },
    schemas::AccessTokenSchema,
    schemas::RefreshTokenSchema,
    schemas::UserCreateSchema,
    schemas::UserLoginSchema,
    schemas::UserTokenSchema,
};

static SQLITE_TUPLE: (&str, &str, i32) = ("database", ".sqlite", 10);

#[post("/register")]
async fn register(request: webJson<UserCreateSchema>) -> Result<impl Responder, Box<dyn Error>> {
    let pool = get_db_pool(SQLITE_TUPLE).await?;
    let post_user = UserCRUD.build_user(&pool, request).await;

    match post_user {
        Ok(user) => {
            let jsonable = json::object! {
            "data" => json::object! {
                "message" => format!("The user, {}, was successfully created!",
                                    user.username.to_string()
                                )
            }
                        };
            return Ok(Response::Ok().body(jsonable.dump()));
        }
        Err(err) => {
            let jsonable = json::object! {
                "detail" => json::object! {
                    "status_code" => 409,
                    "message" => err.to_string()
                }
            };
            return Ok(Response::Conflict().body(jsonable.dump()));
        }
    }
}

#[post("/login")]
async fn login(
    request: webJson<UserLoginSchema>,
    req: HttpRequest,
) -> Result<impl Responder, Box<dyn Error>> {
    check_currently_active(req, "Authorization").await?;

    let grab_user = get_user(request, SQLITE_TUPLE).await?;
    let user = UserTokenSchema {
        username: grab_user.username,
        pk: grab_user.pk,
    };
    let refresh_token = RefreshTokenSchema::get_token_or_create(
        user.username.to_string(),
        get_db_pool(SQLITE_TUPLE).await?,
    )
    .await?;

    match AccessTokenSchema::generate_token(user).await {
        Ok(res) => {
            let jsonable = json::object! {
                "data" => json::object! {
                    "Authorization" => res.token_key.clone()
                }
            };
            let auth_cookie = Cookie::build("Authorization", refresh_token.token_key)
                .http_only(true)
                .secure(true)
                .max_age(Duration::days(7))
                .finish();
            return Ok(Response::build(StatusCode::OK)
                .cookie(auth_cookie)
                .body(jsonable.dump()));
        }
        Err(err) => {
            let jsonable = json::object! {
                "detail" => json::object! {
                    "message" => err.to_string()
                }
            };
            return Ok(Response::BadRequest().body(jsonable.dump()));
        }
    };
}

#[get("/logout")]
async fn logout(req: HttpRequest) -> Result<impl Responder, Box<dyn Error>> {
    let mut res = Response::Ok();

    match check_cookies(req, "Authorization").await {
        Ok(_) => {
            let expired_cookie = Cookie::build("Authorization", "")
            .secure(true)
            .http_only(true)
            .max_age(Duration::days(0))
            .finish();
            res.cookie(expired_cookie);
            
            let jsonable =json::object! {
                "data" => json::object! {
                    "message" => "The user has been successfully logged out."
                }
            };

            return Ok(res.body(jsonable.dump()))
        },
        Err(err) => return Err(Box::new(err))
    }
}

#[delete("/destroy_user")]
async fn destroy_user(req: HttpRequest) -> Result<impl Responder, Box<dyn Error>> {
    check_cookies(req.clone(), "Authorization").await?;
    let token_schema = check_headers(req, "Authorization").await?;
    let user_pk = UserCRUD
        .retrieve_user(&get_db_pool(SQLITE_TUPLE).await?, token_schema.data.pk.to_string())
        .await?;
    let user_operation = UserCRUD.delete_user(&get_db_pool(SQLITE_TUPLE).await?, user_pk.pk.to_string()).await;

    match user_operation {
        Ok(res) => {
            let jsonable: json::JsonValue = json::object! {
                "data" => json::object! {
                    "message" => res.to_string(),
                }
            };
            return Ok(Response::Accepted().body(jsonable.dump()));
        }
        Err(err) => {
            let jsonable: json::JsonValue = json::object! {
                "detail" => json::object! {
                    "status_code" => 500,
                    "message" => err.to_string()
                }
            };
            return Ok(Response::InternalServerError().body(jsonable.dump()));
        }
    }
}


#[get("/refresh")]
async fn token_refresh(req: HttpRequest) -> Result<impl Responder, Box<dyn Error>> {
    let refresh_struct = check_cookies(req, "Authorization").await?;

    let user = UserCRUD.retrieve_user(&get_db_pool(SQLITE_TUPLE).await?, refresh_struct.ref_usernames).await?;    
    let user_token_scheme = UserTokenSchema { username:user.username, pk: user.pk };
    let new_access_token = AccessTokenSchema::generate_token(user_token_scheme).await?;

    let jsonable = json::object! {
        "data" => json::object! {
            "access_token" => new_access_token.token_key
        }
    };
    return Ok(Response::Accepted().body(jsonable.dump()))

}


#[get("/get_user")]
async fn retrieve_user(request: HttpRequest) -> Result<impl Responder, Box<dyn Error>> {

    let handle_token = check_headers(request, "Authorization").await?;
    match UserCRUD.retrieve_user(&get_db_pool(SQLITE_TUPLE).await?, handle_token.data.pk.to_string()).await {
        Ok(user) => {
            let jsonable = json::object! {
                "data" => json::object! {
                    "pk" => user.pk,
                    "username" => user.username,
                    "email" => user.email
                }
            };
            return Ok(Response::Ok().body(jsonable.dump()));
        },
        Err(err) => {
            let err = if err.to_string().contains("no rows") {
                String::from("Wasn't able to locate User")
            } else {
                err.to_string()
            };

            let jsonable: json::JsonValue = json::object! {
                "detail" => json::object! {
                    "status_code" => 500,
                    "message" => err
                }
            };
            return Err(Box::new(actix_web::error::ErrorNotFound(jsonable.dump()))) 
        }
    }
}


pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("auth")
            .service(register)
            .service(destroy_user)
            .service(login)
            .service(token_refresh)
            .service(retrieve_user)
            .service(logout),
    );
}
