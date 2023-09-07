use async_trait_fn::async_trait;
use serde::{Deserialize, Serialize};

use sqlx::FromRow;


#[derive(Debug, Deserialize, Serialize)]
pub struct UserCreateSchema {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserLoginSchema {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct UserBaseSchema {
    pub pk: i64,
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserOutSchema {
    pub email: String,
    pub username: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessTokenSchema {
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub data: UserTokenSchema
}

#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct RefreshTokenSchema {
    pub iat: usize,
    pub exp: usize,
    pub iss: String,
    pub ref_usernames: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserTokenSchema {
    pub username: String,
    pub pk: i64
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenEncoded {
    pub token_key: String,
}

#[async_trait]
pub trait UserTraits {
    fn new(pk: i64, email: String, username: String, password: String) -> UserBaseSchema {
        return UserBaseSchema {
            pk,
            email,
            username,
            password,
        };
    }
}

impl UserTraits for UserBaseSchema {}

pub enum UserIdentifier {
    Email(String),
    Username(String),
    PrimaryKey(i64)
}

impl <T:Into<String>> From<T> for UserIdentifier {
    fn from(value: T) -> Self {
        
        let value = value.into(); 
        match value {
            value if value.contains("@") => UserIdentifier::Email(value),
            pk if pk.parse::<i64>().is_ok() => UserIdentifier::PrimaryKey(pk.parse::<i64>().unwrap()),
            value => UserIdentifier::Username(value)
        }

    }
}
