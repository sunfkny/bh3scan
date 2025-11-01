use hmac::{Hmac, Mac};
use log::trace;
use sha2::Sha256;

use crate::formatter::to_string_with_seperator;

type HmacSha256 = Hmac<Sha256>;

pub fn bh3_sign(data: &str) -> String {
    trace!("data: {}", data);

    let key = b"0ebc517adb1b62c6b408df153331f9aa";
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();

    let sign_bytes = result.into_bytes();
    let sign = hex::encode(sign_bytes);
    trace!("sign: {}", sign);
    sign
}

pub fn bh3_sign_dict(
    data: &serde_json::Map<std::string::String, serde_json::Value>,
) -> serde_json::Map<std::string::String, serde_json::Value> {
    trace!("data: {:#?}", data);
    let mut data_sign = data.clone();
    data_sign.remove("sign");
    data_sign.sort_keys();

    let data_to_sign = data_sign
        .iter()
        .map(|(k, v)| format!("{}={}", k, to_string_with_seperator(v)))
        .collect::<Vec<_>>()
        .join("&");
    trace!("data_to_sign: {}", data_to_sign);

    let sign = bh3_sign(&data_to_sign);
    data_sign.insert("sign".into(), serde_json::Value::String(sign));
    trace!("data: {:#?}", data_sign);
    data_sign
}

#[test]
fn test_bh3_sign_dict() {
    let mut o = serde_json::json!({
        "c":[3,3],
        "b":"2",
        "a": 1,
    });

    let o1 = o.as_object().expect("data should be a object").clone();
    let mut o2 = o
        .as_object_mut()
        .expect("data should be a object mut")
        .clone();
    o2.sort_keys();

    assert_ne!(
        serde_json::to_string(&o1).expect("data should serialize"),
        serde_json::to_string(&o2).expect("data should serialize"),
        "ne because ordering is difference"
    );
    assert_eq!(
        bh3_sign_dict(&o1),
        bh3_sign_dict(&o2),
        "eq because sign dict will sort"
    );
}

#[test]
fn test_bh3_sign_dict_with_object() {
    let body = bh3_sign_dict(
        serde_json::json!({
            "device": "0000000000000000",
            "app_id": 1,
            "channel_id": 14,
            "data": serde_json::json!({
                "uid": "uid",
                "access_key": "access_key",
            }),
        })
        .as_object()
        .expect("data should be a object"),
    );
    println!("{:?}", body);
    assert_eq!(
        body["sign"].as_str().expect("sign should be a str"),
        "5c38352050554333d973ef0a4218e5d4925269fd6ded205ea06048b5111a937f"
    );
}
