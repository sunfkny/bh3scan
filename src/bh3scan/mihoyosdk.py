import hashlib
import hmac
import json
import time

import requests
from cachetools.func import ttl_cache
from loguru import logger

from bh3scan.errors import QRCodeExpiredError, RequestError


def bh3_sign(data: str):
    logger.debug("data: {}", data)
    sign = hmac.new(
        b"0ebc517adb1b62c6b408df153331f9aa",
        data.encode(),
        hashlib.sha256,
    ).hexdigest()
    # logger.debug("sign: {}", sign)
    return sign


def bh3_sign_dict(data: dict):
    data.pop("sign", None)
    data_to_sign_items = []
    for k, v in sorted(data.items()):
        if isinstance(v, dict):
            v = json.dumps(v, separators=(",", ":"))
        data_to_sign_items.append(f"{k}={v}")

    data_to_sign = "&".join(data_to_sign_items)

    sign = bh3_sign(data_to_sign)
    data["sign"] = sign
    return data


@ttl_cache(ttl=60)
def get_bh3_version():
    r = requests.get(
        "https://hyp-api.mihoyo.com/hyp/hyp-connect/api/getGamePackages",
        params={
            "game_ids[]": "osvnlOc0S8",
            "launcher_id": "jGHBHlcOq1",
        },
    )
    logger.debug(f"{r.status_code=} {r.text=}")
    r.raise_for_status()
    version: str = r.json()["data"]["game_packages"][0]["main"]["major"]["version"]
    return version


def qrcode_scan(ticket: str):
    body = {
        "app_id": "1",
        "device": "0000000000000000",
        "ticket": ticket,
        "ts": int(time.time() * 1000),
    }
    body = bh3_sign_dict(body)

    r = requests.post(
        "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/scan",
        json=body,
    )
    logger.debug(f"{r.status_code=} {r.text=}")
    r.raise_for_status()
    retcode = r.json()["retcode"]
    if retcode != 0:
        if retcode == -106:
            raise QRCodeExpiredError(r.text)
        raise RequestError(r.text)
    return ticket


def qrcode_fetch(device: str):
    body = {
        "app_id": "1",
        "device": device,
    }
    r = requests.post(
        "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/fetch",
        json=body,
    )
    logger.debug(
        "status code: {} content: {}",
        r.status_code,
        r.text.encode().decode("unicode_escape"),
    )
    r.raise_for_status()
    if r.json()["retcode"] != 0:
        raise RequestError(r.text)
    ticket_url = r.json()["data"]["url"]
    ticket = ticket_url[-24:]
    return ticket


def qrcode_query(ticket: str, device: str):
    body = {
        "app_id": "1",
        "ticket": ticket,
        "device": device,
    }
    r = requests.post(
        "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/query",
        json=body,
    )
    logger.debug(f"{r.status_code=} {r.text=}")
    r.raise_for_status()
    if r.json()["retcode"] != 0:
        raise RequestError(r.text)
    return r.json()["data"]


def qrcode_confirm(
    asterisk_name: str,
    open_id: str,
    combo_id: str,
    combo_token: str,
    ticket: str,
    dispatch: str,
):
    scan_result = {
        "device": "0000000000000000",
        "app_id": 1,
        "ts": int(time.time() * 1000),
        "ticket": ticket,
        "payload": {
            "raw": (
                json.dumps(
                    {
                        "heartbeat": False,
                        "open_id": open_id,
                        "device_id": "0000000000000000",
                        "app_id": "1",
                        "channel_id": "14",
                        "combo_token": combo_token,
                        "asterisk_name": asterisk_name,
                        "combo_id": combo_id,
                        "account_type": "2",
                    },
                    separators=(",", ":"),
                )
            ),
            "proto": "Combo",
            "ext": (
                json.dumps(
                    {
                        "data": {
                            "accountType": "2",
                            "accountID": open_id,
                            "accountToken": combo_token,
                            "dispatch": dispatch,
                        }
                    },
                    separators=(",", ":"),
                )
            ),
        },
    }
    scan_result = bh3_sign_dict(scan_result)
    r = requests.post(
        "https://api-sdk.mihoyo.com/bh3_cn/combo/panda/qrcode/confirm",
        json=scan_result,
    )
    logger.debug(f"{r.status_code=} {r.text=}")
    r.raise_for_status()
    if r.json()["retcode"] != 0:
        raise RequestError(r.text)


def combo_login(uid: int, access_key: str):
    body = {
        "device": "0000000000000000",
        "app_id": 1,
        "channel_id": 14,
        "data": json.dumps(
            {
                "uid": uid,
                "access_key": access_key,
            }
        ),
    }
    body = bh3_sign_dict(body)
    r = requests.post(
        "https://api-sdk.mihoyo.com/bh3_cn/combo/granter/login/v2/login",
        json=body,
    )
    logger.debug(f"{r.status_code=} {r.text=}")
    r.raise_for_status()
    if r.json()["retcode"] != 0:
        raise RequestError(r.text)
    return r.json()["data"]
