use clap::Parser;
use dns_lookup::lookup_addr;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use regex::Regex;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter},
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    target: String,
}

fn main() {
    let args = Args::parse();

    let geodb_reader = get_geodb().unwrap();

    println!("mapping internet route to '{}'...", args.target);
    let mut traceroute = Command::new("traceroute")
        .arg(args.target)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let hop_line_regex = Regex::new(r"^\s*(?<i>\d+).*\((?<a>[\d\.]+)\)").unwrap();
    let multiprog = MultiProgress::new();
    let multiprog = Arc::new(multiprog);
    let mut thread_handles: Vec<JoinHandle<()>> = vec![];

    for line in BufReader::new(traceroute.stdout.take().unwrap()).lines() {
        if let Ok(line) = line {
            if !hop_line_regex.is_match(&line) {
                continue;
            }

            if let Some(parts) = hop_line_regex.captures(&line) {
                let index: u8 = parts["i"].parse().unwrap();
                let ip_addr = parts["a"].to_string();
                let multiprog = multiprog.clone();

                let handle = thread::spawn(move || {
                    analyse_hop(index, &ip_addr, multiprog);
                });

                thread_handles.push(handle);
            }
        }
    }

    for handle in thread_handles {
        handle.join().unwrap();
    }

    println!("program has completed.");
}

fn get_geodb() -> Result<maxminddb::Reader<Vec<u8>>, Box<dyn std::error::Error>> {
    println!("checking local geo db...");

    if Path::new("res/geo.mmdb").exists() {
        return maxminddb::Reader::open_readfile("/path/to/GeoLite2-City.mmdb")
            .map_err(|e| e.into());
    }

    println!("missing local db. downloading...");
    if !Path::new("res/").exists() {
        fs::create_dir("res")?;
    }

    // got this from https://github.com/P3TERX/GeoLite.mmdb
    // i assume this is ok
    let response = ureq::get("https://git.io/GeoLite2-City.mmdb")
        .call()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }

    let dest = File::create("res/geo.mmdb").unwrap();
    let mut dest_writer = BufWriter::new(dest);
    std::io::copy(&mut response.into_body().into_reader(), &mut dest_writer).unwrap();
    println!("geo db has been downloaded.");

    let reader = maxminddb::Reader::open_readfile("/path/to/GeoLite2-City.mmdb")?;
    return Ok(reader);
}

fn analyse_hop(index: u8, ip_addr_str: &str, multiprog: Arc<MultiProgress>) {
    let progbar = multiprog.add(ProgressBar::new(1));
    progbar.set_style(ProgressStyle::with_template("{prefix}: {msg} {spinner}").unwrap());
    progbar.set_prefix(format!("{:>03}", index));
    progbar.set_message(format!("{:<15} - analysing...", ip_addr_str));
    progbar.enable_steady_tick(Duration::from_millis(100));

    // reverse DNS lookup
    let ip_addr: std::net::IpAddr = ip_addr_str.parse().unwrap();
    let host = lookup_addr(&ip_addr).unwrap_or("unknown".to_string());
    progbar.set_message(format!(
        "{:<15} - analysing...\nhost: {}\n",
        ip_addr_str, host
    ));

    thread::sleep(Duration::from_secs(2));

    progbar.finish_with_message(format!("{}\nhost: {}\n", ip_addr_str, host));
}

//https://git.io/GeoLite2-City.mmdb
