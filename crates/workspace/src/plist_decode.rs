use std::io::Cursor;
use std::path::Path;
use thiserror::Error;

const MAX_ATTACH_PLIST_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_SYSTEM_ENTITIES: usize = 64;
const MAX_DEVICE_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedAttachPlist {
    pub leaf_device_identifier: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttachPlistError {
    #[error("hdiutil attach plist exceeds the bounded input size")]
    TooLarge,
    #[error("hdiutil attach plist is malformed")]
    Malformed,
    #[error("hdiutil attach plist has an invalid structural shape")]
    InvalidStructure,
    #[error("hdiutil attach plist does not contain exactly one mounted leaf")]
    MissingOrAmbiguousLeaf,
    #[error("mount path cannot be represented by the plist string wire")]
    NonUtf8MountPath,
}

pub(crate) fn decode_attach_plist(
    bytes: &[u8],
    expected_mount_path: &Path,
) -> Result<DecodedAttachPlist, AttachPlistError> {
    if bytes.len() > MAX_ATTACH_PLIST_BYTES {
        return Err(AttachPlistError::TooLarge);
    }
    let expected_mount_path = expected_mount_path
        .to_str()
        .ok_or(AttachPlistError::NonUtf8MountPath)?;
    let value =
        plist::Value::from_reader(Cursor::new(bytes)).map_err(|_| AttachPlistError::Malformed)?;
    let root = value
        .as_dictionary()
        .ok_or(AttachPlistError::InvalidStructure)?;
    let entities = root
        .get("system-entities")
        .and_then(plist::Value::as_array)
        .ok_or(AttachPlistError::InvalidStructure)?;
    if entities.is_empty() || entities.len() > MAX_SYSTEM_ENTITIES {
        return Err(AttachPlistError::InvalidStructure);
    }

    let mut leaf = None;
    for entity in entities {
        let dictionary = entity
            .as_dictionary()
            .ok_or(AttachPlistError::InvalidStructure)?;
        let device = dictionary
            .get("dev-entry")
            .and_then(plist::Value::as_string)
            .filter(|value| !value.is_empty() && value.len() <= MAX_DEVICE_IDENTIFIER_BYTES);
        let mount_point = dictionary
            .get("mount-point")
            .and_then(plist::Value::as_string);
        if let (Some(device), Some(mount_point)) = (device, mount_point)
            && mount_point == expected_mount_path
            && leaf.replace(device.to_owned()).is_some()
        {
            return Err(AttachPlistError::MissingOrAmbiguousLeaf);
        }
    }

    Ok(DecodedAttachPlist {
        leaf_device_identifier: leaf.ok_or(AttachPlistError::MissingOrAmbiguousLeaf)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk42</string></dict>
<dict><key>dev-entry</key><string>/dev/disk42s1</string><key>mount-point</key><string>/tmp/bird code mount</string></dict>
</array></dict></plist>"#;

    #[test]
    fn structurally_projects_the_exact_mounted_leaf() {
        let decoded = decode_attach_plist(VALID, Path::new("/tmp/bird code mount"))
            .expect("fixture is structurally valid");
        assert_eq!(decoded.leaf_device_identifier, "/dev/disk42s1");
    }

    #[test]
    fn does_not_guess_a_leaf_from_device_text() {
        let error = decode_attach_plist(VALID, Path::new("/tmp/a different mount"))
            .expect_err("mount identity is an exact structural binding");
        assert_eq!(error, AttachPlistError::MissingOrAmbiguousLeaf);
    }

    #[test]
    fn ignores_other_unmounted_entities_without_device_name_inference() {
        let ambiguous = String::from_utf8(VALID.to_vec())
            .expect("fixture is utf-8")
            .replace(
                "<dict><key>dev-entry</key><string>/dev/disk42</string></dict>",
                "<dict><key>dev-entry</key><string>/dev/disk41</string></dict><dict><key>dev-entry</key><string>/dev/disk42</string></dict>",
            );
        let decoded = decode_attach_plist(ambiguous.as_bytes(), Path::new("/tmp/bird code mount"))
            .expect("only the exact mounted leaf is authority");
        assert_eq!(decoded.leaf_device_identifier, "/dev/disk42s1");
    }
}
