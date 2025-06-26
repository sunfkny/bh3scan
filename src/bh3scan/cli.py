import getpass
import json
import logging
import sys
import time
import typing
import urllib.parse
from typing import Annotated

import pydantic
import pyzbar.pyzbar as zbar
import typer
from loguru import logger
from PIL import ImageGrab
from platformdirs import PlatformDirs
from requests import HTTPError

from bh3scan.errors import (
    AccessTokenExpiredError,
    Bh3ScanBaseError,
    InvalidTicketError,
    QRCodeExpiredError,
)

from . import bsgamesdk, mihoyosdk, scannersdk

dirs = PlatformDirs(appname="bh3scan", appauthor="sunfkny")
app = typer.Typer()


class ZbarDecodedProtocol(typing.Protocol):
    data: bytes
    type: str
    rect: zbar.Rect
    polygon: list[zbar.Point]
    orientation: typing.Literal["UNKNOWN", "UP", "RIGHT", "DOWN", "LEFT"] | None
    quality: int


class LoginData(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    access_key: str
    expires: int
    uid: int

    @pydantic.field_validator("expires", mode="after")
    def validate_expires(cls, v: int):
        if v < (time.time() + 10) * 1000:
            raise AccessTokenExpiredError("Access token expired")
        return v


class ComboLoginData(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")

    open_id: str
    combo_id: str
    combo_token: str


class UserInfo(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="allow")
    uname: str


def check_ticket(ticket: str):
    if ticket.startswith("https://"):
        query = urllib.parse.urlparse(ticket).query
        qs = urllib.parse.parse_qs(query)
        ticket = qs.get("ticket", [""])[0]

    if not ticket:
        raise InvalidTicketError("Ticket is empty")
    return ticket


def get_qr_from_clipboard(max_attempts: int = 60):
    img = ImageGrab.grabclipboard()
    if img is None or isinstance(img, list):
        logger.warning("No image found in clipboard, grab from screen")
        img = ImageGrab.grab()
    attempts = 0
    while attempts < max_attempts:
        results: list[ZbarDecodedProtocol] = zbar.decode(img)
        logger.debug(f"{results=}")
        for qr_data in results:
            if qr_data.data.startswith(b"https://user.mihoyo.com/qr_code_in_game.html"):
                return qr_data.data.decode("utf8")
        logger.info("Waiting for QR code on screen")
        time.sleep(1)
        img = ImageGrab.grab()
        attempts += 1
    logger.error("Maximum attempts reached, QR code not found")
    raise QRCodeExpiredError("Failed to retrieve QR code from clipboard or screen")


@app.command()
def scan(
    ticket: Annotated[
        str,
        typer.Argument(
            help="QR code ticket",
        ),
    ] = "",
    account: Annotated[
        str,
        typer.Option(
            envvar="BH3SCAN_ACCOUNT",
            help="BiliBili account",
        ),
    ] = "",
    password: Annotated[
        str,
        typer.Option(
            envvar="BH3SCAN_PASSWORD",
            help="BiliBili password",
        ),
    ] = "",
    debug: Annotated[
        bool,
        typer.Option(
            envvar="BH3SCAN_DEBUG",
            help="Debug mode",
        ),
    ] = False,
):
    if not debug:
        logger.remove()
        logger.add(sys.stderr, level=logging.INFO)
    dirs.user_log_path.mkdir(parents=True, exist_ok=True)
    logger.add(
        dirs.user_log_path / "debug.log",
        level=logging.DEBUG,
    )

    logger.debug(f"{sys.argv=}")
    logger.debug(f"{ticket=} {account=}")

    if not ticket:
        ticket = get_qr_from_clipboard()

    ticket = check_ticket(ticket)

    version = mihoyosdk.get_bh3_version()

    dispatch = scannersdk.get_query_dispatch(version)

    # step 1: use cache to get access key
    login_data: LoginData | None = None
    dirs.user_data_path.mkdir(parents=True, exist_ok=True)
    if not account:
        accounts_files = list(dirs.user_data_path.glob("account_*.json"))
        logger.debug(f"{accounts_files=}")
        if accounts_files:
            accounts = [
                file.name.removeprefix("account_").removesuffix(".json")
                for file in accounts_files
            ]
            if len(accounts) == 1:
                account = accounts[0]
            else:
                logger.error(
                    f"Found multiple accounts {accounts}, use --account to specify"
                )
                sys.exit(1)

    login_cache_file = dirs.user_data_path / f"account_{account}.json"
    if login_cache_file.exists():
        logger.debug(f"{login_cache_file=} exists")
        login_cache_file_content = login_cache_file.read_text(encoding="utf8")
        logger.debug(f"{login_cache_file_content=}")

        try:
            login_data = LoginData.model_validate_json(login_cache_file_content)
        except pydantic.ValidationError as e:
            logger.error(e)
            logger.warning("Invalid login cache file")
            login_cache_file.unlink(missing_ok=True)

    # step 2: no cache or cache expired, login
    if login_data is None:
        if not password:
            password = getpass.getpass(f"Password for {account}: ")
        login_response = bsgamesdk.login(account, password)
        try:
            login_data = LoginData.model_validate(login_response)
        except pydantic.ValidationError as e:
            logger.error(e)
            raise Bh3ScanBaseError(f"Invalid login response {login_response}")

        # save login cache
        login_cache_file.write_text(json.dumps(login_response), encoding="utf8")

    user_info_response = bsgamesdk.get_user_info(login_data.uid, login_data.access_key)
    try:
        user_info = UserInfo.model_validate(user_info_response)
    except pydantic.ValidationError as e:
        logger.error(e)
        raise Bh3ScanBaseError(f"Invalid user_info response {user_info_response}")

    # step 3: use access key to scan
    combo_login_response = mihoyosdk.combo_login(
        uid=login_data.uid,
        access_key=login_data.access_key,
    )
    try:
        combo_login_data = ComboLoginData.model_validate(combo_login_response)
    except pydantic.ValidationError as e:
        logger.error(e)
        logger.error(f"Invalid combo login response {combo_login_response}")
        sys.exit(1)

    try:
        mihoyosdk.qrcode_scan(ticket)
    except QRCodeExpiredError:
        while True:
            try:
                ticket = input("Ticket: ")
                ticket = check_ticket(ticket)
                mihoyosdk.qrcode_scan(ticket)
                break
            except QRCodeExpiredError as e:
                logger.error(f"QR code expired {e}")
                continue
            except InvalidTicketError as e:
                logger.error(f"Invalid ticket {e}")
                continue
            except Bh3ScanBaseError as e:
                logger.error(e)
                continue

    mihoyosdk.qrcode_confirm(
        asterisk_name=user_info.uname,
        open_id=combo_login_data.open_id,
        combo_id=combo_login_data.combo_id,
        combo_token=combo_login_data.combo_token,
        ticket=ticket,
        dispatch=dispatch,
    )


def main():
    try:
        app()
    except Bh3ScanBaseError as e:
        logger.error(e)
        sys.exit(1)
    except HTTPError as e:
        logger.error(e)
        sys.exit(1)
    except Exception:
        logger.exception("Unhandled exception")
        sys.exit(1)
