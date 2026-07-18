use serde_json::Value;

pub(crate) fn encode(value: &Value) -> Result<String, serde_json::Error> {
    let mut encoded = String::new();
    write_value(value, &mut encoded)?;
    Ok(encoded)
}

fn write_value(value: &Value, encoded: &mut String) -> Result<(), serde_json::Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            encoded.push_str(&serde_json::to_string(value)?);
        }
        Value::Array(values) => {
            encoded.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    encoded.push(',');
                }
                write_value(value, encoded)?;
            }
            encoded.push(']');
        }
        Value::Object(values) => {
            encoded.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    encoded.push(',');
                }
                encoded.push_str(&serde_json::to_string(key)?);
                encoded.push(':');
                write_value(value, encoded)?;
            }
            encoded.push('}');
        }
    }
    Ok(())
}
