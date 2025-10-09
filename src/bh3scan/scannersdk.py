import time

from cachetools.func import ttl_cache

from bh3scan.errors import RequestError
from bh3scan.mihoyosdk import bh3_sign
from bh3scan.request import session


@ttl_cache(ttl=60)
def get_query_dispatch(version: str):
    openid = 0
    timestamp = int(time.time())
    params = {
        "version": f"{version}_gf_android_bilibili",
        "t": timestamp,
    }
    header = {
        "x-req-code": "80",
        "x-req-name": "pc-1.4.7:80",
        "x-req-openid": f"{openid}",
        "x-req-version": f"{version}_gf_android_bilibili",
    }
    header_to_sign = "&".join(f"{k}={v}" for k, v in header.items())
    header["x-req-sign"] = bh3_sign(header_to_sign)

    r = session.get(
        url="https://dispatch.scanner.hellocraft.xyz/v3/query_dispatch/",
        params=params,
        headers=header,
    )
    r.raise_for_status()
    retcode = r.json()["retcode"]
    if retcode != 0:
        raise RequestError(r.text)
    return r.json()["data"]
