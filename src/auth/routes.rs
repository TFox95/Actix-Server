use actix_web::{
    cookie::time::Duration, cookie::Cookie, delete, get, http::StatusCode, post, web::scope,
    web::Json as webJson, web::ServiceConfig, HttpRequest, HttpResponse as Response, Responder,
};

use std::error::Error;
use std::result::Result;

use super::{
    crud::UserCRUD,
    middleware::{
        check_auth_header,
        check_currently_active,
        check_auth_cookies, 
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
        user.username.clone(),
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

#[delete("/destroy_user")]
async fn destroy_user(request: webJson<UserLoginSchema>) -> Result<impl Responder, Box<dyn Error>> {
    let pool = get_db_pool(SQLITE_TUPLE).await?;
    let user_pk = UserCRUD
        .retrieve_user_by_username_or_email(&pool, request.username.to_string())
        .await?;
    let user_operation = UserCRUD.delete_user(&pool, user_pk.pk).await;

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
                    "message" => err.to_string()
                }
            };
            return Ok(Response::InternalServerError().body(jsonable.dump()));
        }
    }
}


#[get("/refresh")]
async fn token_refresh(req: HttpRequest) -> Result<impl Responder, Box<dyn Error>> {
    let refresh_struct = check_auth_cookies(req, "Authorization").await?;

    let user = UserCRUD.retrieve_user_by_username_or_email(&get_db_pool(SQLITE_TUPLE).await?, refresh_struct.ref_usernames).await?;    
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

    let handle_token = check_auth_header(request, "Authorization").await?;
    let handle_user = UserCRUD.retrieve_user_by_pk(&get_db_pool(SQLITE_TUPLE).await?, handle_token.pk).await?;

    let jsonable = json::object! {
        "data" => json::object! {
            "pk" => handle_user.pk,
            "username" => handle_user.username,
            "email" => handle_user.email,
            "password" => handle_user.password
        }
    };

    return Ok(Response::Ok().body(jsonable.dump()));
}


pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        scope("auth")
            .service(register)
            .service(destroy_user)
            .service(login)
            .service(token_refresh),
    );
}
