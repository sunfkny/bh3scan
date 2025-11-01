use crate::sdk::sign::bh3_sign;
use log::debug;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerSDKErr {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Retcode Error: {retcode:?} - {body}")]
    Retcode { retcode: Option<i64>, body: String },
    #[error(transparent)]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("Status Error: {status} - {url} - {body}")]
    StatusError {
        status: reqwest::StatusCode,
        url: String,
        body: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetQueryDispatchQuery {
    version: String,
    t: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetQueryDispatchResponse {
    retcode: Option<i64>,
    message: Option<String>,
    data: Option<String>,
}

pub struct ScannerSDK {}
impl ScannerSDK {
    pub async fn get_query_dispatch(version: &str) -> Result<String, ScannerSDKErr> {
        let openid = 0;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let params = GetQueryDispatchQuery {
            version: format!("{version}_gf_android_bilibili"),
            t: timestamp,
        };
        let mut headers = HeaderMap::new();
        for (k, v) in [
            ("x-req-code", "80"),
            ("x-req-name", "pc-1.4.7:80"),
            ("x-req-openid", &openid.to_string()),
            ("x-req-version", &format!("{version}_gf_android_bilibili")),
        ] {
            headers.insert(k, HeaderValue::from_str(v)?);
        }

        let header_to_sign = headers
            .iter()
            .filter_map(|(k, v)| match v.to_str() {
                Ok(v) => Some((k.as_str(), v)),
                Err(_) => None,
            })
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        headers.insert(
            "x-req-sign",
            HeaderValue::from_str(bh3_sign(&header_to_sign).as_str())?,
        );

        let url = "https://dispatch.scanner.hellocraft.xyz/v3/query_dispatch/";
        let response = reqwest::Client::builder()
            .build()?
            .get(url)
            .headers(headers)
            .query(&params)
            .send()
            .await?;

        let status = response.status();
        debug!("Status: {:?}", status);
        let headers = response.headers();
        debug!("Headers: {:?}", headers);
        let body = response.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(ScannerSDKErr::StatusError {
                status,
                url: url.into(),
                body,
            });
        }

        let data: GetQueryDispatchResponse = serde_json::from_str(&body)?;

        match data.retcode {
            Some(0) => Ok(data.data.expect("data should set with retcode 0")),
            retcode => Err(ScannerSDKErr::Retcode { retcode, body }),
        }
    }
}
