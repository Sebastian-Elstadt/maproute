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

struct HopInfo {
    index: u8,
    ip_addr: std::net::IpAddr,
    dns_host: String,
    geo_addr: String,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    target: String,
}

fn main() {
    let args = Args::parse();

    let geodb = Arc::new(get_geodb().unwrap());

    println!("mapping internet route to '{}'...", args.target);
    let mut traceroute = Command::new("traceroute")
        .arg(args.target)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let hop_line_regex = Regex::new(r"^\s*(?<i>\d+).*\((?<a>[\d\.]+)\)").unwrap();
    let multiprog = Arc::new(MultiProgress::new());
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
                let geodb = geodb.clone();

                let handle = thread::spawn(move || {
                    analyse_hop(index, &ip_addr, multiprog, geodb);
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
        return maxminddb::Reader::open_readfile("res/geo.mmdb").map_err(|e| e.into());
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

fn analyse_hop(
    index: u8,
    ip_addr_str: &str,
    multiprog: Arc<MultiProgress>,
    geodb: Arc<maxminddb::Reader<Vec<u8>>>,
) {
    let mut hop = HopInfo {
        index,
        ip_addr: ip_addr_str.parse().unwrap(),
        dns_host: "...".to_string(),
        geo_addr: "...".to_string(),
    };

    let progbar = multiprog.add(ProgressBar::new(1));
    progbar.set_style(ProgressStyle::with_template("{prefix}: {msg} {spinner}").unwrap());
    progbar.set_prefix(format!("{:>03}", index));
    update_hop_progress(&hop, &progbar, false);
    progbar.enable_steady_tick(Duration::from_millis(100));

    // reverse DNS lookup
    hop.dns_host = lookup_addr(&hop.ip_addr).unwrap_or("unknown".to_string());
    update_hop_progress(&hop, &progbar, false);

    // geo lookup
    let geo_result = geodb.lookup(hop.ip_addr).unwrap();
    if let Ok(Some(city)) = geo_result.decode::<maxminddb::geoip2::City>() {
        hop.geo_addr = format!(
            "{}, {}",
            city.city.names.english.unwrap_or("???"),
            city.country.names.english.unwrap_or("???")
        );
    } else {
        hop.geo_addr = "unknown".to_string();
    }
    update_hop_progress(&hop, &progbar, false);

    // finalise
    update_hop_progress(&hop, &progbar, true);
}

fn update_hop_progress(hop: &HopInfo, progbar: &ProgressBar, finished: bool) {
    if finished {
        progbar.set_message(format!(
            "{}\nhost: {}\ngeo: {}\n",
            hop.ip_addr, hop.dns_host, hop.geo_addr
        ));
    } else {
        progbar.finish_with_message(format!(
            "{:<15} - analysing...\nhost: {}\ngeo: {}\n",
            hop.ip_addr, hop.dns_host, hop.geo_addr
        ));
    }
}
