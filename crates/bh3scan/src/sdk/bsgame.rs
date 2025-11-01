use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, warn};
use md5::{Digest, Md5};
use reqwest::header::{HeaderMap, HeaderValue};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BsGameSDKErr {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Retcode Error {code}: {message}")]
    RetCode { code: i64, message: String },
    #[error("SecondaryVerify Error: {message}")]
    SecondaryVerify { message: String },
    #[error("Status Error: {status} - {url} - {body}")]
    StatusError {
        status: reqwest::StatusCode,
        url: String,
        body: String,
    },
    #[error(transparent)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("RSA Error: {0}")]
    RsaError(String),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
struct ChapchaResponse {
    challenge: String,
    gt: String,
    gt_user_id: String,
}

pub struct BsGameSDK;
impl BsGameSDK {
    fn rsa_create(message: &str, public_key: &str) -> Result<String, BsGameSDKErr> {
        // Public key returned by server may be raw base64 or already a PEM.
        // Trim whitespace and accept either form.
        let pk = public_key.trim();
        let pem = if pk.starts_with("-----BEGIN") {
            pk.to_string()
        } else {
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
                pk
            )
        };
        let public_key = RsaPublicKey::from_public_key_pem(&pem)
            .map_err(|e| BsGameSDKErr::RsaError(e.to_string()))?;

        let mut rng = rand::rng();
        let enc_data = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
            .map_err(|e| BsGameSDKErr::RsaError(e.to_string()))?;

        Ok(BASE64_STANDARD.encode(&enc_data))
    }

    fn bili_sign(data: &mut BTreeMap<String, String>) -> Result<(), BsGameSDKErr> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        data.insert("timestamp".to_string(), timestamp.to_string());
        data.insert("client_timestamp".to_string(), timestamp.to_string());

        let mut data_to_sign = String::new();
        for (_, v) in data.iter() {
            data_to_sign.push_str(v);
        }
        data_to_sign.push_str("dbf8f1b4496f430b8a3c0f436a35b931");

        let mut hasher = Md5::new();
        hasher.update(data_to_sign.as_bytes());
        let sign = hex::encode(hasher.finalize());
        data.insert("sign".to_string(), sign);

        Ok(())
    }

    async fn send_bili_post(
        url: &str,
        data: BTreeMap<String, String>,
    ) -> Result<serde_json::Value, BsGameSDKErr> {
        debug!("Send Bili Post: {url}");
        let mut data = data;
        Self::bili_sign(&mut data)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "User-Agent",
            HeaderValue::from_static("Mozilla/5.0 BSGameSDK"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let client = reqwest::Client::new();
        let res = client.post(url).headers(headers).form(&data).send().await?;

        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(BsGameSDKErr::StatusError {
                status,
                url: url.into(),
                body,
            });
        }

        let json: serde_json::Value = serde_json::from_str(&body)?;
        let code = json["code"].as_i64().unwrap_or(-1);
        let message = json["message"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_default();
        match code {
            0 => Ok(json),
            200000 => Err(BsGameSDKErr::SecondaryVerify { message }),
            _ => Err(BsGameSDKErr::RetCode { code, message }),
        }
    }

    pub async fn get_user_info(
        uid: i64,
        access_key: &str,
    ) -> Result<serde_json::Value, BsGameSDKErr> {
        let data: BTreeMap<String, String> = serde_json::json!({
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "sdk_type": "1",
            "isRoot": "0",
            "merchant_id": "590",
            "dp": "1280*720",
            "mac": "08:00:27:53:DD:12",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "operators": "5",
            "fingerprint": "",
            "model": "MuMu",
            "udid": "XXA31CBAB6CBA63E432E087B58411A213BFB7",
            "net": "5",
            "app_id": "180",
            "brand": "Android",
            "oaid": "",
            "game_id": "180",
            "ver": "6.1.0",
            "c": "1",
            "version_code": "510",
            "server_id": "378",
            "version": "1",
            "domain_switch_count": "0",
            "pf_ver": "12",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "original_domain": "",
            "imei": "",
            "sdk_log_type": "1",
            "sdk_ver": "3.4.2",
            "android_id": "84567e2dda72d1d4",
            "channel_id": "1",
            "uid": uid.to_string(),
            "access_key": access_key.to_string(),
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/user.info",
            data,
        )
        .await
    }

    pub async fn login1(account: &str, password: &str) -> Result<serde_json::Value, BsGameSDKErr> {
        let rsa_data: BTreeMap<String, String> = serde_json::json!({
            "operators": "5",
            "merchant_id": "590",
            "isRoot": "0",
            "domain_switch_count": "0",
            "sdk_type": "1",
            "sdk_log_type": "1",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "sdk_ver": "3.4.2",
            "oaid": "",
            "dp": "1280*720",
            "original_domain": "",
            "imei": "",
            "version": "1",
            "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "android_id": "84567e2dda72d1d4",
            "fingerprint": "",
            "mac": "08:00:27:53:DD:12",
            "server_id": "378",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "app_id": "180",
            "version_code": "510",
            "net": "4",
            "pf_ver": "12",
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "c": "1",
            "brand": "Android",
            "channel_id": "1",
            "game_id": "180",
            "ver": "6.1.0",
            "model": "MuMu",
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        let rsa = Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/rsa",
            rsa_data,
        )
        .await?;

        let public_key = rsa["rsa_key"].as_str().expect("rsa_key should be a str");
        let hash = rsa["hash"].as_str().expect("hash should be a str");

        let mut login_data: BTreeMap<String, String> = serde_json::json!({
            "operators": "5",
            "merchant_id": "590",
            "isRoot": "0",
            "domain_switch_count": "0",
            "sdk_type": "1",
            "sdk_log_type": "1",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "sdk_ver": "3.4.2",
            "oaid": "",
            "dp": "1280*720",
            "original_domain": "",
            "imei": "227656364311444",
            "version": "1",
            "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "android_id": "84567e2dda72d1d4",
            "fingerprint": "",
            "mac": "08:00:27:53:DD:12",
            "server_id": "378",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "app_id": "180",
            "version_code": "510",
            "net": "4",
            "pf_ver": "12",
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "c": "1",
            "brand": "Android",
            "channel_id": "1",
            "game_id": "180",
            "ver": "6.1.0",
            "model": "MuMu",
            "access_key": "",
            "gt_user_id": "",
            "uid": "",
            "challenge": "",
            "user_id": account.to_string(),
            "validate": "",
            "pwd": "",
            "captcha_type": "1",
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        login_data.insert(
            "pwd".to_string(),
            Self::rsa_create(&format!("{}{}", hash, password), public_key)?,
        );

        Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/login",
            login_data,
        )
        .await
    }

    pub async fn login2(
        account: &str,
        password: &str,
        challenge: &str,
        gt_user: &str,
        validate: &str,
    ) -> Result<serde_json::Value, BsGameSDKErr> {
        let rsa_data: BTreeMap<String, String> = serde_json::json!({
            "operators": "5",
            "merchant_id": "590",
            "isRoot": "0",
            "domain_switch_count": "0",
            "sdk_type": "1",
            "sdk_log_type": "1",
            "timestamp": "1613035485639",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "access_key": "",
            "sdk_ver": "3.4.2",
            "oaid": "",
            "dp": "1280*720",
            "original_domain": "",
            "imei": "",
            "version": "1",
            "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "android_id": "84567e2dda72d1d4",
            "fingerprint": "",
            "mac": "08:00:27:53:DD:12",
            "server_id": "378",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "app_id": "180",
            "version_code": "510",
            "net": "4",
            "pf_ver": "12",
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "c": "1",
            "brand": "Android",
            "client_timestamp": "1613035486888",
            "channel_id": "1",
            "uid": "",
            "game_id": "180",
            "ver": "6.1.0",
            "model": "MuMu",
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        let rsa = Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/rsa",
            rsa_data,
        )
        .await?;

        let public_key = rsa["rsa_key"].as_str().expect("rsa_key should be a str");
        let hash = rsa["hash"].as_str().expect("hash should be a str");

        let mut login_data: BTreeMap<String, String> = serde_json::json!({
            "operators": "5",
            "merchant_id": "590",
            "isRoot": "0",
            "domain_switch_count": "0",
            "sdk_type": "1",
            "sdk_log_type": "1",
            "timestamp": "1613035508188",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "access_key": "",
            "sdk_ver": "3.4.2",
            "oaid": "",
            "dp": "1280*720",
            "original_domain": "",
            "imei": "227656364311444",
            "version": "1",
            "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "android_id": "84567e2dda72d1d4",
            "fingerprint": "",
            "mac": "08:00:27:53:DD:12",
            "server_id": "378",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "app_id": "180",
            "version_code": "510",
            "net": "4",
            "pf_ver": "12",
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "c": "1",
            "brand": "Android",
            "client_timestamp": "1613035509437",
            "channel_id": "1",
            "uid": "",
            "captcha_type": "1",
            "game_id": "180",
            "user_id": "doo349",
            "ver": "6.1.0",
            "model": "MuMu",
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        login_data.insert("gt_user_id".to_string(), gt_user.to_string());
        login_data.insert("challenge".to_string(), challenge.to_string());
        login_data.insert("user_id".to_string(), account.to_string());
        login_data.insert("validate".to_string(), validate.to_string());
        login_data.insert("seccode".to_string(), format!("{}|jordan", validate));
        login_data.insert(
            "pwd".to_string(),
            Self::rsa_create(&format!("{}{}", hash, password), public_key)?,
        );

        Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/login",
            login_data,
        )
        .await
    }

    pub async fn captcha() -> Result<serde_json::Value, BsGameSDKErr> {
        let data: BTreeMap<String, String> = serde_json::json!({
            "operators": "5",
            "merchant_id": "590",
            "isRoot": "0",
            "domain_switch_count": "0",
            "sdk_type": "1",
            "sdk_log_type": "1",
            "timestamp": "1613035486182",
            "support_abis": "x86,armeabi-v7a,armeabi",
            "access_key": "",
            "sdk_ver": "3.4.2",
            "oaid": "",
            "dp": "1280*720",
            "original_domain": "",
            "imei": "227656364311444",
            "version": "1",
            "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
            "apk_sign": "4502a02a00395dec05a4134ad593224d",
            "platform_type": "3",
            "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "android_id": "84567e2dda72d1d4",
            "fingerprint": "",
            "mac": "08:00:27:53:DD:12",
            "server_id": "378",
            "domain": "line1-sdk-center-login-sh.biligame.net",
            "app_id": "180",
            "version_code": "510",
            "net": "4",
            "pf_ver": "12",
            "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
            "c": "1",
            "brand": "Android",
            "client_timestamp": "1613035487431",
            "channel_id": "1",
            "uid": "",
            "game_id": "180",
            "ver": "6.1.0",
            "model": "MuMu",
        })
        .as_object()
        .expect("data should be a object")
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_str().unwrap_or_default().to_string()))
        .collect();

        Self::send_bili_post(
            "https://line1-sdk-center-login-sh.biligame.net/api/client/start_captcha",
            data,
        )
        .await
    }

    pub async fn login(account: &str, password: &str) -> Result<serde_json::Value, BsGameSDKErr> {
        let login_result = Self::login1(account, password).await;

        match login_result {
            Ok(_) => login_result,
            Err(BsGameSDKErr::SecondaryVerify { message }) => {
                warn!("{:?}", message);
                let cap = Self::captcha().await?;

                let ChapchaResponse {
                    challenge,
                    gt,
                    gt_user_id,
                } = serde_json::from_value(cap)?;

                let url = format!(
                    "https://help.tencentbot.top/geetest/?captcha_type=1&challenge={}&gt={}&userid={}&gs=1",
                    challenge, gt, gt_user_id
                );

                println!("Please open this URL in your browser: {}", url);

                print!("validate: ");
                io::stdout().flush()?;
                let mut validate = String::new();
                io::stdin().read_line(&mut validate)?;
                let validate = validate.trim();

                Self::login2(account, password, &challenge, &gt_user_id, validate).await
            }
            _ => login_result,
        }
    }
}
