use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const CACHE_URL: &str =
    "https://raw.githubusercontent.com/tn3w/Ripplit/master/captcha_icons.cache.xz";
const CACHE_FILE: &str = "captcha_icons.cache";

fn main() {
    if Path::new(CACHE_FILE).exists() {
        return;
    }

    eprintln!("Downloading icon cache...");

    let mut response = ureq::get(CACHE_URL)
        .call()
        .expect("Failed to download cache file");

    let mut compressed = Vec::new();
    std::io::copy(&mut response.body_mut().as_reader(), &mut compressed)
        .expect("Failed to read response");

    eprintln!("Decompressing cache...");

    let mut decompressor = xz2::read::XzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decompressor
        .read_to_end(&mut decompressed)
        .expect("Failed to decompress");

    let mut file = File::create(CACHE_FILE).expect("Failed to create cache file");
    file.write_all(&decompressed)
        .expect("Failed to write cache file");

    eprintln!("Icon cache ready");
}
