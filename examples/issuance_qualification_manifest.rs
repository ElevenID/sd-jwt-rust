// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sd_jwt_rs::issuer::issuance_benchmark::issuance_qualification_manifest_json;

const USAGE: &str = "usage: issuance_qualification_manifest --output <absolute-new-file>";

fn output_path<I>(arguments: I) -> Result<PathBuf, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let flag = arguments.next().ok_or_else(|| USAGE.to_owned())?;
    let path = arguments.next().ok_or_else(|| USAGE.to_owned())?;
    if flag != "--output" || arguments.next().is_some() {
        return Err(USAGE.to_owned());
    }

    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("--output must name an absolute path".to_owned());
    }
    Ok(path)
}

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(contents)?;
    output.flush()?;
    output.sync_all()
}

fn run() -> Result<(), String> {
    let path = output_path(env::args_os().skip(1))?;
    let manifest = issuance_qualification_manifest_json();
    write_new_file(&path, manifest.as_bytes())
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

    fn unique_output_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must follow the Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "sd-jwt-issuance-manifest-{}-{nonce}-{}.json",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[test]
    fn parser_accepts_only_the_exact_absolute_output_form() {
        let absolute = env::temp_dir().join("manifest.json");
        assert_eq!(
            output_path([
                OsString::from("--output"),
                absolute.clone().into_os_string()
            ])
            .unwrap(),
            absolute
        );

        for arguments in [
            Vec::new(),
            vec![OsString::from("--output")],
            vec![OsString::from("manifest.json")],
            vec![OsString::from("--output"), OsString::from("manifest.json")],
            vec![
                OsString::from("--output"),
                env::temp_dir().join("manifest.json").into_os_string(),
                OsString::from("unexpected"),
            ],
            vec![
                OsString::from("--other"),
                env::temp_dir().join("manifest.json").into_os_string(),
            ],
        ] {
            assert!(output_path(arguments).is_err());
        }
    }

    #[test]
    fn emitter_creates_once_and_preserves_an_existing_file() {
        let path = unique_output_path();
        let manifest = issuance_qualification_manifest_json();
        write_new_file(&path, manifest.as_bytes()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), manifest.as_bytes());

        let error = write_new_file(&path, b"replacement").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), manifest.as_bytes());

        fs::remove_file(path).unwrap();
    }
}
