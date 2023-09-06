use crate::utils::config::Hasher;
use std::env::var;
use std::error::Error as stdError;

use actix_web::web::Json as webJson;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode as JWTencode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::{query, Pool, Row, Sqlite};

use super::schemas::{
    AccessTokenSchema, RefreshTokenSchema, TokenEncoded, UserBaseSchema, UserCreateSchema,
    UserOutSchema, UserTokenSchema, UserTraits, UserIdentifier,
};

pub struct UserCRUD;
impl UserCRUD {

    pub async fn retrieve_user(
        &self,
        sql_pool: &Pool<Sqlite>,
        identifier: impl Into<UserIdentifier>
        ) -> Result<UserBaseSchema, Box<dyn stdError>> {
        
        let identifier = identifier.into();

        let query_statement = match identifier {
            UserIdentifier::Email(email) => {
                let sql =  "SELECT * FROM users WHERE email = $1";
                query(sql).bind(email).fetch_one(sql_pool).await?
            },
            UserIdentifier::Username(username) => {
                let sql =  "SELECT * FROM users WHERE username = $1";
                query(sql).bind(username).fetch_one(sql_pool).await?
            },
            UserIdentifier::PrimaryKey(pk) =>  {
                let sql = "SELECT * FROM users WHERE pk = $1";
                query(sql).bind(pk).fetch_one(sql_pool).await?
            }
        };
        
        let decoded = UserBaseSchema::new(
            query_statement.get("pk"), 
            query_statement.get("email"), 
            query_statement.get("username"), 
            query_statement.get("password")
            );
        
        return Ok(decoded)
    }

    pub async fn build_user(
        &self,
        sql_pool: &Pool<Sqlite>,
        mut user: webJson<UserCreateSchema>,
    ) -> Result<UserOutSchema, Box<dyn stdError>> {
        let sql = "INSERT INTO users (email, username, password) VALUES ($1, $2, $3)";

        user.password = AuthHandler.get_password_hash(&user.password);

        query(sql)
            .bind(&user.email)
            .bind(&user.username)
            .bind(&user.password)
            .execute(sql_pool)
            .await?;

        return Ok(UserOutSchema {
            email: user.email.clone(),
            username: user.username.clone(),
        });
    }

    pub async fn update_user_parameter(
        &self,
        sql_pool: &Pool<Sqlite>,
        identifier: impl Into<UserIdentifier>,
        targetd_parameter: String,
        mut updated_value: String,
    ) -> Result<String, Box<dyn stdError>> {

        let identifier = identifier.into();
        let result = match &identifier {
            UserIdentifier::Username(username) => {
                let sql = "SELECT $1 FROM users WHERE username = $2";
                query(sql).bind(&targetd_parameter.to_lowercase()).bind(username).fetch_optional(sql_pool).await?
            },
            UserIdentifier::Email(email) => {
                let sql = "SELECT $1 FROM users WHERE email = $2";
                query(sql).bind(&targetd_parameter.to_lowercase()).bind(email).fetch_optional(sql_pool).await?
            },
            UserIdentifier::PrimaryKey(pk) => {
                let sql = "SELECT $1 FROM users WHERE pk = $2";
                query(sql).bind(&targetd_parameter.to_lowercase()).bind(pk).fetch_optional(sql_pool).await?
            }
        };

        let user_result = result.as_ref().map(|row| -> UserBaseSchema {
            UserBaseSchema::new(row.get("pk"), row.get("email"), row.get("username"), row.get("password"))
        });

        if targetd_parameter.to_lowercase() == String::from("password") {
            updated_value = AuthHandler.get_password_hash(&updated_value)
        };

        let current_value: String = result.map(|row| -> String {row.get(targetd_parameter.as_str())}).unwrap().to_string();
        if updated_value == current_value {
            let jsonable = json::object! {
                "detail" => json::object! {
                    "status_code" => 409,
                    "message" => format!("Unable to update the {}. The value provided for the new {} does not meet the length, complexity, or history requirements of the domain", targetd_parameter, targetd_parameter)
                }
            };
            return Err(Box::new(actix_web::error::ErrorBadRequest(jsonable.dump())))
        };
                    
        let sql = "UPDATE users SET $1 = $2 WHERE pk = $3";
        match query(sql).bind(targetd_parameter.to_lowercase()).bind(updated_value).bind(&user_result.unwrap().pk.to_string()).fetch_one(sql_pool).await {
            Ok(_) => return Ok(String::from("The user's password has been updated.")),
            Err(err) => {
                let jsonable = json::object! {
                    "detail" => json::object! {
                        "status_code" => 409,
                        "message" => err.to_string()
                    }
                };
                return Err(Box::new(actix_web::error::ErrorInternalServerError(jsonable.dump())))
            }
        } 
    }

    pub async fn delete_user(
        &self,
        sql_pool: &Pool<Sqlite>,
        identifier: impl Into<UserIdentifier>
    ) -> Result<String, Box<dyn stdError>> {
        
        let identifier = identifier.into();

        let _ = match identifier {
            UserIdentifier::Email(email) => {
                let sql = "DELETE FROM users WHERE email = $1";
                query(sql).bind(email).execute(sql_pool).await?
            },
            UserIdentifier::Username(username) => {
                let sql = "DELETE FROM users WHERE username = $1";
                query(sql).bind(username).execute(sql_pool).await?
            },
            UserIdentifier::PrimaryKey(pk) => {
                let sql = "DELETE FROM users WHERE pk = $1";
                query(sql).bind(pk).execute(sql_pool).await?
            }
        };

        return Ok(String::from(
            "User has been successfully removed from database.",
        ));
    }
}

pub struct AuthHandler;
impl AuthHandler {
    pub fn get_password_hash(&self, psw: &str) -> String {
        return Hasher::encode(psw, "sha_256");
    }

    pub fn verify_password(&self, psw: &str, encoded_psw: &str) -> bool {
        return Hasher::verify(psw, encoded_psw);
    }
}

impl RefreshTokenSchema {
    pub async fn get_token_or_create(
        username: String,
        pool: Pool<Sqlite>,
    ) -> Result<TokenEncoded, actix_web::Error> {
        let sql = "SELECT * FROM tokens WHERE ref_usernames = $1";

        let check_db = query(sql).bind(&username).fetch_one(&pool);

        match check_db.await {
            Ok(res) => {
                let refresh_exp: i64 = res.get("exp");
                let current_time: i64 = Utc::now().timestamp();

                if current_time > refresh_exp {
                    let sql = "DELETE FROM tokens WHERE ref_usernames = $1";
                    let check_query = query(sql).bind(username).execute(&pool).await;

                    match check_query {
                        Ok(_res) => return {
                            let jsonable = json::object! {
                                        "detail" => json::object! {
                                    "message" => "Please Log back in"
                                }
                            };

                            Err(actix_web::error::ErrorNotFound(jsonable.dump()))
                        },
                        Err(_err) => {
                            let jsonable = json::object! {
                                        "detail" => json::object! {
                                    "message" => "Session Expired"
                                }
                            };
                            return Err(actix_web::error::ErrorUnauthorized(jsonable.dump()));
                        }
                    }
                } else {
                    let token_key: &str = res.get("token_key");
                    return Ok(TokenEncoded{token_key: format!("Bearer={}", token_key)})
                }
            }
            Err(err) => {
                println!("{}", err.to_string());
                let issued_at = Utc::now();
                let expiration = Utc::now() + Duration::days(7);
                let issuer = String::from("Rust Actix-web Restful Api");
                let claims = RefreshTokenSchema {
                    iat: issued_at.timestamp() as usize,
                    exp: expiration.timestamp() as usize,
                    iss: issuer,
                    ref_usernames: username.clone(),
                };
                let jwt_encoded_key =
                    EncodingKey::from_secret(var("jwt_secret_key").unwrap().as_bytes());
                let header = Header::default();
                let jwt = JWTencode(&header, &claims, &jwt_encoded_key).unwrap();

                let sql = "INSERT INTO tokens (token_key, iat, exp, ref_usernames) VALUES ($1, $2, $3, $4)";
                let execute_query = query(sql)
                    .bind(&jwt)
                    .bind(&issued_at.timestamp())
                    .bind(&expiration.timestamp())
                    .bind(&username)
                    .execute(&pool)
                    .await;
                match execute_query {
                    Ok(_res) => return Ok(TokenEncoded { token_key: format!("Bearer={}", jwt.to_string()) }),
                    Err(err) => {
                        let jsonable = json::object! {
                                    "detail" => json::object! {
                                "message" =>  err.to_string()
                            }
                        };
                        return Err(actix_web::error::ErrorUnauthorized(jsonable.dump()));
                    }
                }
            }
        }
    }

    pub async fn decode_access_token(
        token: TokenEncoded,
    ) -> Result<RefreshTokenSchema, Box<dyn stdError>> {
        let jwt_secret_key = var("jwt_secret_key").unwrap().as_bytes().to_owned();
        let jwt_decoding_key = DecodingKey::from_secret(&jwt_secret_key.as_ref());
        let decoded = decode::<RefreshTokenSchema>(
            &token.token_key,
            &jwt_decoding_key,
            &Validation::default(),
        )?;

        return Ok(RefreshTokenSchema {
            exp: decoded.claims.exp,
            iat: decoded.claims.iat,
            iss: decoded.claims.iss,
            ref_usernames: decoded.claims.ref_usernames
        });
    }
}

impl AccessTokenSchema {
    pub async fn generate_token(user: UserTokenSchema) -> Result<TokenEncoded, Box<dyn stdError>> {
        let issued_at = Utc::now().timestamp(); //Time Token was issued,
        let expiration = Utc::now() + Duration::minutes(15); //Time Token Expires,
        let issuer: String = String::from("Rust Actix-web Restful Api"); //Token Issuer.
        let claims = AccessTokenSchema {
            //Define refresh Token.
            exp: expiration.timestamp() as usize,
            iat: issued_at as usize,
            iss: issuer,
            data: UserTokenSchema { 
                username: user.username, 
                pk: user.pk 
            }
        };

        let jwt_secret_key = var("jwt_secret_key").unwrap().as_bytes().to_owned(); //unwraping jwt secret from .env file and converting it to bytes.
        let jwt_encoded_secret = EncodingKey::from_secret(&jwt_secret_key.as_ref()); //Defining the Encoding Key and passing the jwt secret to it as bytes.
        let header = Header::default(); // Defining the default hashing algorithm HS256.
        let mut jwt = JWTencode(&header, &claims, &jwt_encoded_secret)?;
        jwt = format!("Bearer={}", jwt);

        return Ok(TokenEncoded { token_key: jwt });
    }

    pub async fn decode_access_token(
        token: TokenEncoded,
    ) -> Result<AccessTokenSchema, Box<dyn stdError>> {
        let jwt_secret_key = var("jwt_secret_key").unwrap().as_bytes().to_owned();
        let jwt_decoding_key = DecodingKey::from_secret(&jwt_secret_key.as_ref());
        let decoded = decode::<AccessTokenSchema>(
            &token.token_key,
            &jwt_decoding_key,
            &Validation::default(),
        )?;

        return Ok(decoded.claims)
    }
}
