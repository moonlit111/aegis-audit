//! Windows DPAPI model credentials. Legacy plaintext is read only for compatibility.
use anyhow::{Result, ensure};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

pub const PREFIX: &str = "aegis-dpapi-v1:";

struct ProtectedBuffer(CRYPT_INTEGER_BLOB);
impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        unsafe {
            for index in 0..self.0.cbData as usize {
                self.0.pbData.add(index).write_volatile(0);
            }
            LocalFree(self.0.pbData.cast());
        }
    }
}

pub fn encode(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= 16384,
        "invalid credential size"
    );
    let mut bytes = value.as_bytes().to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let succeeded = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    bytes.fill(0);
    ensure!(
        succeeded != 0,
        "credential protection failed for this Windows account"
    );
    let output = ProtectedBuffer(output);
    let protected =
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
    Ok(format!("{PREFIX}{}", hex::encode(protected)))
}

pub fn decode(value: &str) -> Result<String> {
    let value = value.trim();
    let Some(encoded) = value.strip_prefix(PREFIX) else {
        ensure!(
            !value.starts_with("aegis-dpapi-"),
            "unsupported protected credential version"
        );
        return Ok(value.into());
    };
    ensure!(encoded.len() <= 131072, "protected credential is too large");
    let mut bytes =
        hex::decode(encoded).map_err(|_| anyhow::anyhow!("invalid protected credential"))?;
    ensure!(!bytes.is_empty(), "empty protected credential");
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let succeeded = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    ensure!(
        succeeded != 0,
        "credential cannot be decrypted by this Windows account; configure it again"
    );
    let output = ProtectedBuffer(output);
    ensure!(
        output.0.cbData <= 16384 && !output.0.pbData.is_null(),
        "invalid decrypted credential size"
    );
    let bytes = unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
    String::from_utf8(bytes.to_vec())
        .map_err(|_| anyhow::anyhow!("invalid decrypted credential encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Cryptography::CryptProtectData;

    #[test]
    fn dpapi_roundtrip_and_corruption_do_not_expose_the_credential() {
        let secret = "fixture-only-windows-credential";
        let mut bytes = secret.as_bytes().to_vec();
        let input = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        assert_ne!(
            unsafe {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut output,
                )
            },
            0
        );
        let output = ProtectedBuffer(output);
        let bytes =
            unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
        let protected = format!("{PREFIX}{}", hex::encode(bytes));
        assert!(!protected.contains(secret));
        assert_eq!(decode(&protected).unwrap(), secret);
        for invalid in [
            format!("{PREFIX}00"),
            format!("{PREFIX}not-hex"),
            "aegis-dpapi-v2:00".into(),
        ] {
            assert!(decode(&invalid).is_err());
        }
        assert_eq!(decode(secret).unwrap(), secret);
    }
}
