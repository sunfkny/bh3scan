use serde::Serialize;

#[derive(Clone, Debug)]
pub struct SeparatorFormatter {
    item: &'static str,
    key: &'static str,
}

impl SeparatorFormatter {
    pub fn new() -> Self {
        Self {
            item: ", ",
            key: ": ",
        }
    }
}

impl Default for SeparatorFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl serde_json::ser::Formatter for SeparatorFormatter {
    #[inline]
    fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        writer.write_all(self.key.as_bytes())
    }

    #[inline]
    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(self.item.as_bytes())
        }
    }
}

pub trait WithFormatter<T>
where
    T: serde_json::ser::Formatter,
{
    fn to_string_with_formatter(&self, formatter: T) -> Result<String, serde_json::Error>;
}

impl<T> WithFormatter<T> for serde_json::Value
where
    Self: serde::Serialize,
    T: serde_json::ser::Formatter,
{
    fn to_string_with_formatter(&self, formatter: T) -> Result<String, serde_json::Error> {
        let mut writer = Vec::with_capacity(128);
        let mut ser = serde_json::Serializer::with_formatter(&mut writer, formatter);
        self.serialize(&mut ser)?;
        // Safety: the serializer below only emits valid utf8 when using
        // the default formatter.
        let string = unsafe { String::from_utf8_unchecked(writer) };
        Ok(string)
    }
}

pub fn to_string_with_seperator(value: &serde_json::Value) -> String {
    if value.is_string() {
        return value.as_str().map(|s| s.to_string()).unwrap_or_default();
    }
    if value.is_object() || value.is_array() {
        return value
            .to_string_with_formatter(SeparatorFormatter::default())
            .unwrap_or_default();
    }
    serde_json::to_string(value).unwrap_or_default()
}
