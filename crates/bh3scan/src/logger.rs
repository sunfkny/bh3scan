use log::LevelFilter;
use log4rs::{
    append::{
        console::ConsoleAppender,
        rolling_file::{
            RollingFileAppender,
            policy::compound::{
                CompoundPolicy, roll::fixed_window::FixedWindowRoller,
                trigger::onstartup::OnStartUpTrigger,
            },
        },
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};
use std::path::Path;

const MB: u64 = 1024 * 1024;

pub fn setup_logger(path: impl AsRef<Path>, debug: bool) {
    let path = path.as_ref();

    let console_encoder = Box::new(PatternEncoder::new(if debug {
        "[{d(%Y-%m-%dT%H:%M:%S.%3f)} {h({l})} {f}:{L}] {m}{n}"
    } else {
        "[{d(%Y-%m-%dT%H:%M:%S.%3f)} {h({l})} {M}:{L}] {m}{n}"
    }));
    let console_appender = ConsoleAppender::builder().encoder(console_encoder).build();

    let trigger = OnStartUpTrigger::new(MB);
    let roller = FixedWindowRoller::builder()
        .build(path.join("debug.{}.log").to_string_lossy().as_ref(), 7)
        .expect("invalid roller config");

    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    let file_encoder = Box::new(PatternEncoder::new(
        "[{d(%Y-%m-%dT%H:%M:%S.%3f)} {l} {f}:{L}] {m}{n}",
    ));
    let file_appender = RollingFileAppender::builder()
        .encoder(file_encoder)
        .build(path.join("debug.log"), Box::new(policy))
        .expect("failed to create file appender");

    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(if debug {
                    LevelFilter::Debug
                } else {
                    LevelFilter::Info
                })))
                .build("console", Box::new(console_appender)),
        )
        .appender(Appender::builder().build("file", Box::new(file_appender)))
        .build(
            Root::builder()
                .appender("console")
                .appender("file")
                .build(LevelFilter::Debug),
        )
        .expect("failed to build logger config");

    log4rs::init_config(config).expect("failed to init logger");
}
