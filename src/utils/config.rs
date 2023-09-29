use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sha2::{Digest, Sha256, Sha512};
use std::env::var;
use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn get_server_time() -> Result<DateTime<Utc>, Box<dyn Error>> {
    let now = SystemTime::now();
    let since_epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("Failed to get time since epoch");
    let unix_time: i64 = since_epoch.as_secs().try_into().unwrap();
    let datetimestruct: Option<NaiveDateTime> = NaiveDateTime::from_timestamp_opt(unix_time, 0);

    match datetimestruct {
        Some(datetime) => {
            let datetime_utc: DateTime<Utc> = Utc.from_utc_datetime(&datetime);
            return Ok(datetime_utc);
        }
        _ => {
            println!("Invalid UNIX timestamp");
            return Err("Invalid UNIX timestamp".into());
        }
    }
}

pub struct Hasher;

impl Hasher {
    pub fn encode(key: &str, algorithm: &str) -> String {
        let salt: String = var("HASH_SALT").unwrap();
        let pepper: String = var("HASH_PEPPER").unwrap();

        let salt_key_pepper: String = format!("{}{}{}", salt, key, pepper);

        match algorithm.to_lowercase().as_str() {
            "256" | "sha_256" => {
                let mut hashing = Sha256::new();
                hashing.update(salt_key_pepper.as_str());
                let final_hash = format!("{:x}", hashing.finalize());

                return final_hash;
            }
            "512" | "sha_512" => {
                let mut hashing = Sha512::new();
                hashing.update(salt_key_pepper.as_str());
                let final_hash = format!("{:x}", hashing.finalize());
                return final_hash;
            }

            _ => panic!(
                "Incoorect Arguments passed to encode function. Check arguments and try again."
            ),
        }
    }

    pub fn verify(key: &str, encoded_key: &str) -> bool {
        
        if key == encoded_key {
            return true
        } else if key != encoded_key {
            return false
        } else {
            panic!("Incorrect Arguments passed to encode function. Check arguments and try again.")
        }
        
    }
}
