import base64
import hashlib
import time
import webbrowser

from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

from bh3scan.request import session


def rsacreate(message: str, public_key):
    rsakey = RSA.importKey(public_key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(message.encode()))
    text = cipher_text.decode()
    return text


def bili_sign(data: dict):
    timestamp = int(time.time())
    data["timestamp"] = timestamp
    data["client_timestamp"] = timestamp

    data_to_sign_items: list[str] = []
    for k, v in sorted(data.items()):
        data_to_sign_items.append((str(v)))
    data_to_sign_items.append("dbf8f1b4496f430b8a3c0f436a35b931")
    data_to_sign = "".join(data_to_sign_items)
    sign = hashlib.md5(data_to_sign.encode()).hexdigest()
    data["sign"] = sign
    return data


def send_bili_post(url, data: dict) -> dict:
    data = bili_sign(data.copy())
    header = {
        "User-Agent": "Mozilla/5.0 BSGameSDK",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    r = session.post(url=url, data=data, headers=header)
    r.raise_for_status()
    return r.json()


user_info_param = {
    "cur_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
    "client_timestamp": "1667057013442",
    "sdk_type": "1",
    "isRoot": "0",
    "merchant_id": "590",
    "dp": "1280*720",
    "mac": "08:00:27:53:DD:12",
    "uid": "",
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
    "timestamp": "1667057013275",
    "ver": "6.1.0",
    "c": "1",
    "version_code": "510",
    "server_id": "378",
    "version": "1",
    "domain_switch_count": "0",
    "pf_ver": "12",
    "access_key": "",
    "domain": "line1-sdk-center-login-sh.biligame.net",
    "original_domain": "",
    "imei": "",
    "sdk_log_type": "1",
    "sdk_ver": "3.4.2",
    "android_id": "84567e2dda72d1d4",
    "channel_id": 1,
}
rsa_param = {
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
}
login_param = {
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
    "gt_user_id": "fac83ce4326d47e1ac277a4d552bd2af",
    "seccode": "",
    "version": "1",
    "udid": "KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",
    "apk_sign": "4502a02a00395dec05a4134ad593224d",
    "platform_type": "3",
    "old_buvid": "XZA2FA4AC240F665E2F27F603ABF98C615C29",
    "android_id": "84567e2dda72d1d4",
    "fingerprint": "",
    "validate": "84ec07cff0d9c30acb9fe46b8745e8df",
    "mac": "08:00:27:53:DD:12",
    "server_id": "378",
    "domain": "line1-sdk-center-login-sh.biligame.net",
    "app_id": "180",
    "pwd": "rxwA8J+GcVdqa3qlvXFppusRg4Ss83tH6HqxcciVsTdwxSpsoz2WuAFFGgQKWM1+GtFovrLkpeMieEwOmQdzvDiLTtHeQNBOiqHDfJEKtLj7h1nvKZ1Op6vOgs6hxM6fPqFGQC2ncbAR5NNkESpSWeYTO4IT58ZIJcC0DdWQqh4=",
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
    "challenge": "efc825eaaef2405c954a91ad9faf29a2",
    "user_id": "doo349",
    "ver": "6.1.0",
    "model": "MuMu",
}
captcha_param = {
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
}


def get_user_info(uid: int, access_key: str):
    data = user_info_param.copy()
    data["uid"] = uid
    data["access_key"] = access_key
    return send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/user.info", data
    )


def login1(account: str, password: str):
    data = rsa_param.copy()
    rsa = send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/rsa", data
    )
    public_key = rsa["rsa_key"]
    data = login_param.copy()
    data["access_key"] = ""
    data["gt_user_id"] = ""
    data["uid"] = ""
    data["challenge"] = ""
    data["user_id"] = account
    data["validate"] = ""
    data["pwd"] = rsacreate(rsa["hash"] + password, public_key)
    return send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/login", data
    )


def login2(account, password, challenge, gt_user, validate):
    data = rsa_param.copy()
    rsa = send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/rsa", data
    )
    public_key = rsa["rsa_key"]
    data = login_param.copy()
    data["access_key"] = ""
    data["gt_user_id"] = gt_user
    data["uid"] = ""
    data["challenge"] = challenge
    data["user_id"] = account
    data["validate"] = validate
    data["seccode"] = validate + "|jordan"
    data["pwd"] = rsacreate(rsa["hash"] + password, public_key)
    return send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/login", data
    )


def captcha():
    data = captcha_param.copy()
    return send_bili_post(
        "https://line1-sdk-center-login-sh.biligame.net/api/client/start_captcha", data
    )


def login(bili_account, bili_pwd):
    login_sta = login1(bili_account, bili_pwd)
    if login_sta["code"] == 200000:
        cap = captcha()
        challenge = cap["challenge"]
        gt = cap["gt"]
        userid = cap["gt_user_id"]
        webbrowser.open(
            f"https://help.tencentbot.top/geetest/?captcha_type=1&challenge={challenge}&gt={gt}&userid={userid}&gs=1"
        )
        validate = input("validate: ")
        login_sta = login2(bili_account, bili_pwd, challenge, userid, validate)
    return login_sta
