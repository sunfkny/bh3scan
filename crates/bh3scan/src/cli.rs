use crate::logger::setup_logger;
use crate::sdk::mihoyo::ComboLoginResponse;
use crate::sdk::{bsgame, mihoyo, scanner};
use arboard::Clipboard;
use clap::Parser;
use directories::ProjectDirs;
use image::{GrayImage, ImageBuffer};
use log::{debug, info, warn};
use rpassword::read_password;
use rqrr::PreparedImage;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::fs;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct LoginResponse {
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    uid: i64,
}

#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    #[serde(default)]
    uname: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "bh3scan CLI", long_about = None)]
pub struct CliArgs {
    #[arg(default_value_t = String::new())]
    pub ticket: String,

    #[arg(short, long, env = "BH3SCAN_ACCOUNT")]
    pub account: Option<String>,

    #[arg(short, long, env = "BH3SCAN_PASSWORD")]
    pub password: Option<String>,

    #[arg(long, env = "BH3SCAN_DEBUG", default_value_t = false)]
    pub debug: bool,
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error(transparent)]
    Mihoyo(#[from] mihoyo::MihoyoSDKErr),
    #[error(transparent)]
    BsGame(#[from] bsgame::BsGameSDKErr),
    #[error(transparent)]
    Scanner(#[from] scanner::ScannerSDKErr),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Input canceled")]
    Canceled,
}

pub async fn run() -> Result<(), CliError> {
    let dirs = ProjectDirs::from("com", "sunfkny", "bh3scan")
        .ok_or_else(|| std::io::Error::other("Cannot determine project dirs"))?;

    let args = CliArgs::parse();

    setup_logger(dirs.data_local_dir(), args.debug);

    let ticket_arg = if args.ticket.is_empty() {
        None
    } else {
        Some(args.ticket)
    };
    let mut account = args.account;
    let mut password = args.password;

    info!("Getting game version");
    let version = mihoyo::MihoyoSDK::get_version().await?;
    debug!("version: {}", version);

    info!("Getting dispatch");
    let dispatch = scanner::ScannerSDK::get_query_dispatch(&version).await?;
    debug!("dispatch len: {}", dispatch.len());

    let ticket = match ticket_arg {
        Some(t) => check_ticket(&t)?,
        None => {
            // try clipboard once
            if let Some(t) = get_qr_from_clipboard()? {
                t
            } else if let Some(t) = get_qr_from_screen()? {
                t
            } else {
                debug!("reading ticket from stdin");
                print!("Ticket: ");
                io::stdout().flush()?;
                let mut s = String::new();
                io::stdin().read_line(&mut s)?;
                let s = s.trim().to_string();
                check_ticket(&s)?
            }
        }
    };
    info!("ticket: {}", ticket);

    if account.is_none() {
        debug!("reading account from stdin");
        print!("Account: ");
        io::stdout().flush()?;
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        account = Some(s.trim().to_string());
    }

    let account = account.expect("account must be set");

    info!("[1/6] Checking cached login status");
    let user_data_dir = dirs.data_local_dir();
    fs::create_dir_all(user_data_dir)?;
    let login_cache_file = user_data_dir.join(format!("account_{}.json", account));
    let mut login_resp_value: Option<JsonValue> = None;
    if login_cache_file.exists() {
        let content = fs::read_to_string(&login_cache_file)?;
        match serde_json::from_str::<JsonValue>(&content) {
            Ok(v) => {
                // validate expires (assume milliseconds since epoch)
                if let Some(expires) = v["expires"].as_i64() {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(std::io::Error::other)?
                        .as_millis() as i64;
                    if expires > now_ms + 10_000 {
                        debug!("Using cached login status for account {}", account);
                        login_resp_value = Some(v);
                    } else {
                        info!("Cached login expired, removing cache file");
                        let _ = fs::remove_file(&login_cache_file);
                    }
                } else {
                    // invalid cache format
                    let _ = fs::remove_file(&login_cache_file);
                }
            }
            Err(_) => {
                let _ = fs::remove_file(&login_cache_file);
            }
        }
    }

    let login_resp: JsonValue = if let Some(v) = login_resp_value {
        info!("[2/6] Using cached login status");
        v
    } else {
        if password.is_none() {
            debug!("reading password securely from stdin");
            print!("Password: ");
            io::stdout().flush()?;
            let p = read_password().map_err(std::io::Error::other)?;
            password = Some(p);
        }

        let password = password.expect("password must be set");

        info!("[2/6] Logging in to BiliBili");
        let resp = bsgame::BsGameSDK::login(&account, &password).await?;
        // try to persist login response
        if let Ok(s) = serde_json::to_string(&resp) {
            let _ = fs::write(&login_cache_file, s);
        }
        resp
    };
    let LoginResponse { access_key, uid } = serde_json::from_value(login_resp)?;

    info!("[3/6] Getting user info");
    let user_info_resp = bsgame::BsGameSDK::get_user_info(uid, &access_key).await?;
    let UserInfoResponse { uname } = serde_json::from_value(user_info_resp)?;

    info!("[4/6] Connecting to game server");
    let ComboLoginResponse {
        open_id,
        combo_id,
        combo_token,
    } = mihoyo::MihoyoSDK::combo_login(uid, &access_key).await?;

    info!("[5/6] Sending QR code");
    match mihoyo::MihoyoSDK::qrcode_scan(&ticket).await {
        Ok(_) => {}
        Err(mihoyo::MihoyoSDKErr::QRCodeExpiredError { text }) => {
            warn!("{}", text);
            info!("QR code expired, please input a new ticket");
            loop {
                print!("Ticket: ");
                io::stdout().flush()?;
                let mut t = String::new();
                io::stdin().read_line(&mut t)?;
                let t = t.trim().to_string();
                let t = check_ticket(&t)?;
                match mihoyo::MihoyoSDK::qrcode_scan(&t).await {
                    Ok(_) => break,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                }
            }
        }
        Err(e) => {
            return Err(CliError::Mihoyo(e));
        }
    }

    info!("[6/6] Confirming login");
    mihoyo::MihoyoSDK::qrcode_confirm(
        &uname,
        &open_id,
        &combo_id,
        &combo_token,
        &ticket,
        &dispatch,
    )
    .await?;

    debug!("Login confirmed");

    Ok(())
}

fn check_ticket(ticket: &str) -> Result<String, CliError> {
    debug!("Checking ticket: {}", ticket);
    if ticket.starts_with("https://")
        && let Some(pos) = ticket.find("ticket=")
    {
        let val = &ticket[pos + "ticket=".len()..];
        let val = val.split('&').next().unwrap_or("");
        if val.is_empty() {
            return Err(CliError::Canceled);
        }
        return Ok(val.to_string());
    }

    if ticket.is_empty() {
        return Err(CliError::Canceled);
    }
    Ok(ticket.to_string())
}

fn get_qr_from_clipboard() -> Result<Option<String>, CliError> {
    info!("Trying to read QR from clipboard");
    if let Ok(mut clipboard) = Clipboard::new()
        && let Ok(img) = clipboard.get_image()
        && let Some(s) = decode_qr_from_arboard_image(&img)
    {
        return Ok(Some(s));
    }
    Ok(None)
}

fn get_qr_from_screen() -> Result<Option<String>, CliError> {
    info!("Trying to read QR from screens");
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300);

    // Get all displays and create capturers first
    let displays = match scrap::Display::all() {
        Ok(displays) => displays,
        Err(e) => {
            warn!("Failed to get displays: {}", e);
            return Ok(None);
        }
    };

    let mut capturers = Vec::new();
    for display in displays {
        match scrap::Capturer::new(display) {
            Ok(capturer) => {
                let width = capturer.width();
                let height = capturer.height();
                debug!("Created screen capturer: {}x{}", width, height);
                capturers.push((capturer, width, height));
            }
            Err(e) => warn!("Failed to create capturer: {}", e),
        }
    }
    info!("Created {} capturers", capturers.len());

    if capturers.is_empty() {
        warn!("No valid screen capturers created");
        return Ok(None);
    }

    let frame_wait = Duration::from_millis(1);
    loop {
        for (pos, (capturer, width, height)) in capturers.iter_mut().enumerate() {
            debug!("Trying capturer {} ({},{})", pos, *width, *height);
            'inner: loop {
                if start.elapsed() > timeout {
                    debug!("Screen capture timeout after {}s", timeout.as_secs());
                    return Ok(None);
                }
                match capturer.frame() {
                    Ok(frame) => {
                        let buf = frame.to_vec();
                        if let Some(s) = decode_qr_from_bgra(&buf, *width as u32, *height as u32) {
                            debug!("Successfully decoded QR from screen");
                            return Ok(Some(s));
                        } else {
                            debug!("No QR code found in frame");
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("Frame not ready, waiting {:?}", frame_wait);
                            sleep(frame_wait);
                            continue 'inner;
                        }
                        warn!("Failed to capture frame: {}", e);
                    }
                }
                break 'inner;
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let delay_secs = (0.1 * 2f64.powf(elapsed / (60.0 / f64::log2(10.0)))).min(300.0);
        debug!("Sleeping for {:.2}s before next capture", delay_secs);
        sleep(Duration::from_secs_f64(delay_secs));
    }
}

fn decode_qr_from_arboard_image(img: &arboard::ImageData) -> Option<String> {
    decode_qr_from_bgra(&img.bytes, img.width as u32, img.height as u32)
}

fn decode_qr_from_bgra(buf: &[u8], width: u32, height: u32) -> Option<String> {
    if buf.len() < (width as usize) * (height as usize) * 4 {
        return None;
    }

    let mut luma = Vec::with_capacity((width * height) as usize);
    for chunk in buf.chunks_exact(4) {
        let b = chunk[0] as f32;
        let g = chunk[1] as f32;
        let r = chunk[2] as f32;
        let y = (0.299 * r + 0.587 * g + 0.114 * b).round() as u8;
        luma.push(y);
    }

    let gray: GrayImage = ImageBuffer::from_raw(width, height, luma)?;

    let mut prepared = PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            let s = content;
            if s.starts_with("https://user.mihoyo.com/qr_code_in_game.html") {
                if let Some(pos) = s.find("ticket=") {
                    let val = &s[pos + "ticket=".len()..];
                    let val = val.split('&').next().unwrap_or("");
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
                return Some(s);
            } else {
                return Some(s);
            }
        }
    }

    None
}
