use crate::sdk::sign::bh3_sign_dict;
use log::debug;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MihoyoSDKErr {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Retcode Error: {retcode} - {body}")]
    Retcode { retcode: String, body: String },
    #[error("No Retcode - {body}")]
    NoRetcode { body: String },
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
    #[error("QRCode Expired: {text}")]
    QRCodeExpiredError { text: String },
    #[error("Json Parse Error: {field} - {body}")]
    JsonParseError { field: String, body: String },
}

#[derive(Debug, Deserialize)]
pub struct ComboLoginResponse {
    pub open_id: String,
    pub combo_id: String,
    pub combo_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ComboScanResponse {
    // #[serde(default)]
    // pub passport_qr_url: String,
}

#[derive(Debug, Deserialize)]
pub struct ComboResponse<T> {
    pub retcode: Option<i64>,
    pub data: Option<T>,
}

pub struct MihoyoSDK;
impl MihoyoSDK {
    pub async fn get_version() -> Result<String, MihoyoSDKErr> {
        let client = reqwest::Client::new();
        let url = "https://bbs-api.miyoushe.com/reception/wapi/gameDetail?id=14";
        debug!("Url: {}", url);
        let res = client.get(url).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let version = json["data"]["item"]["config"]["pkg"]["pkg_version"]
            .as_str()
            .ok_or_else(|| MihoyoSDKErr::JsonParseError {
                field: "pkg_version".to_string(),
                body: body.to_string(),
            })?;
        Ok(version.to_string())
    }

    pub async fn qrcode_scan(ticket: &str) -> Result<ComboScanResponse, MihoyoSDKErr> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let body = bh3_sign_dict(
            serde_json::json!({
                "app_id": "1",
                "device": "0000000000000000",
                "ticket": ticket,
                "ts": ts,
            })
            .as_object()
            .ok_or_else(|| MihoyoSDKErr::JsonParseError {
                field: "body".to_string(),
                body: "Failed to create request body".to_string(),
            })?,
        );

        let client = reqwest::Client::new();
        let url = "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/scan";
        debug!("Url: {}", url);
        let res = client.post(url).json(&body).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let combo_data: ComboResponse<ComboScanResponse> = serde_json::from_str(&body)?;
        match combo_data {
            ComboResponse {
                retcode: Some(0),
                data: Some(data),
            } => Ok(data),

            ComboResponse {
                retcode: Some(-106),
                ..
            } => Err(MihoyoSDKErr::QRCodeExpiredError {
                text: body.to_string(),
            }),
            ComboResponse {
                retcode: Some(retcode),
                ..
            } => Err(MihoyoSDKErr::Retcode {
                retcode: retcode.to_string(),
                body,
            }),
            _ => Err(MihoyoSDKErr::NoRetcode { body }),
        }
    }

    // TODO: remove this function
    #[allow(dead_code)]
    pub async fn qrcode_fetch(device: &str) -> Result<String, MihoyoSDKErr> {
        let body = serde_json::json!({
            "app_id": "1",
            "device": device,
        });
        let client = reqwest::Client::new();
        let url = "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/fetch";
        debug!("Url: {}", url);
        let res = client.post(url).json(&body).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let retcode = json["retcode"].as_i64();
        match retcode {
            Some(0) => {
                let ticket_url =
                    json["data"]["url"]
                        .as_str()
                        .ok_or_else(|| MihoyoSDKErr::JsonParseError {
                            field: "url".to_string(),
                            body: body.to_string(),
                        })?;
                let ticket = ticket_url.split('/').next_back().ok_or_else(|| {
                    MihoyoSDKErr::JsonParseError {
                        field: "ticket".to_string(),
                        body: ticket_url.to_string(),
                    }
                })?;
                Ok(ticket.to_string())
            }
            _ => Err(MihoyoSDKErr::Retcode {
                retcode: retcode.map(|s| s.to_string()).unwrap_or_default(),
                body: body.to_string(),
            }),
        }
    }

    // TODO: remove this function
    #[allow(dead_code)]
    pub async fn qrcode_query(
        ticket: &str,
        device: &str,
    ) -> Result<serde_json::Value, MihoyoSDKErr> {
        let body = serde_json::json!({
            "app_id": "1",
            "ticket": ticket,
            "device": device,
        });
        let client = reqwest::Client::new();
        let url = "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/query";
        debug!("Url: {}", url);
        let res = client.post(url).json(&body).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let retcode = json["retcode"].as_i64();
        match retcode {
            Some(0) => Ok(json["data"].clone()),
            _ => Err(MihoyoSDKErr::Retcode {
                retcode: retcode.map(|s| s.to_string()).unwrap_or_default(),
                body: body.to_string(),
            }),
        }
    }

    pub async fn qrcode_confirm(
        asterisk_name: &str,
        open_id: &str,
        combo_id: &str,
        combo_token: &str,
        ticket: &str,
        dispatch: &str,
    ) -> Result<(), MihoyoSDKErr> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let raw = serde_json::json!({
            "heartbeat": false,
            "open_id": open_id,
            "device_id": "0000000000000000",
            "app_id": "1",
            "channel_id": "14",
            "combo_token": combo_token,
            "asterisk_name": asterisk_name,
            "combo_id": combo_id,
            "account_type": "2",
        });

        let ext = serde_json::json!({
            "data": {
                "accountType": "2",
                "accountID": open_id,
                "accountToken": combo_token,
                "dispatch": dispatch,
            }
        });

        let body = bh3_sign_dict(
            serde_json::json!({
                "device": "0000000000000000",
                "app_id": 1,
                "ts": ts,
                "ticket": ticket,
                "payload": {
                    "raw": raw.to_string(),
                    "proto": "Combo",
                    "ext": ext.to_string(),
                }
            })
            .as_object()
            .ok_or_else(|| MihoyoSDKErr::JsonParseError {
                field: "body".to_string(),
                body: "Failed to create request body".to_string(),
            })?,
        );

        let client = reqwest::Client::new();
        let url = "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/confirm";
        debug!("Url: {}", url);
        let res = client.post(url).json(&body).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let combo_data: ComboResponse<serde_json::Value> = serde_json::from_str(&body)?;
        match combo_data {
            ComboResponse {
                retcode: Some(0), ..
            } => Ok(()),
            ComboResponse {
                retcode: Some(retcode),
                ..
            } => Err(MihoyoSDKErr::Retcode {
                retcode: retcode.to_string(),
                body,
            }),
            _ => Err(MihoyoSDKErr::NoRetcode { body }),
        }
    }

    pub async fn combo_login(
        uid: i64,
        access_key: &str,
    ) -> Result<ComboLoginResponse, MihoyoSDKErr> {
        let body = bh3_sign_dict(
            serde_json::json!({
                "device": "0000000000000000",
                "app_id": 1,
                "channel_id": 14,
                "data": serde_json::json!({
                    "uid": uid,
                    "access_key": access_key,
                }).to_string(),
            })
            .as_object()
            .ok_or_else(|| MihoyoSDKErr::JsonParseError {
                field: "body".to_string(),
                body: "Failed to create request body".to_string(),
            })?,
        );

        let client = reqwest::Client::new();
        let url = "https://api-sdk.mihoyo.com/bh3_cn/combo/granter/login/v2/login";
        debug!("Url: {}", url);
        let res = client.post(url).json(&body).send().await?;
        let status = res.status();
        debug!("Status: {:?}", status);
        let headers = res.headers();
        debug!("Headers: {:?}", headers);
        let body = res.text().await?;
        debug!("Body: {}", body);
        if !status.is_success() {
            return Err(MihoyoSDKErr::StatusError {
                status,
                url: url.to_string(),
                body: body.to_string(),
            });
        }
        let combo_data: ComboResponse<ComboLoginResponse> = serde_json::from_str(&body)?;
        match combo_data {
            ComboResponse {
                retcode: Some(0),
                data: Some(data),
            } => Ok(data),
            ComboResponse {
                retcode: Some(retcode),
                ..
            } => Err(MihoyoSDKErr::Retcode {
                retcode: retcode.to_string(),
                body,
            }),
            _ => Err(MihoyoSDKErr::NoRetcode { body }),
        }
    }
}
