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

#[derive(Debug)]
struct WhoIsResult {
    net_name: String,
    desc: String,
    country: String,
    status: String,
    source: String,
    person: String,
    address: String,
    created: String,
}

impl WhoIsResult {
    fn new_filled(str: &str) -> Self {
        let str = str.to_string();

        WhoIsResult {
            net_name: str.clone(),
            desc: str.clone(),
            country: str.clone(),
            status: str.clone(),
            source: str.clone(),
            person: str.clone(),
            address: str.clone(),
            created: str.clone(),
        }
    }
}

struct HopInfo {
    ip_addr: std::net::IpAddr,
    dns_host: String,
    geo_addr: String,
    whois: WhoIsResult,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    target: String,
}

fn main() {
    let args = Args::parse();

    let geo_db = Arc::new(get_geo_db().unwrap());
    let whois_db = Arc::new(get_whois_db().unwrap());

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
                let geo_db = geo_db.clone();
                let whois_db = whois_db.clone();

                let handle = thread::spawn(move || {
                    analyse_hop(index, &ip_addr, multiprog, geo_db, whois_db);
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

fn download_resource_file(url: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("res/").exists() {
        fs::create_dir("res")?;
    }

    let response = ureq::get(url)
        .call()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }

    let dest = File::create(format!("res/{}", file)).unwrap();
    let mut dest_writer = BufWriter::new(dest);
    std::io::copy(&mut response.into_body().into_reader(), &mut dest_writer).unwrap();

    Ok(())
}

fn get_geo_db() -> Result<maxminddb::Reader<Vec<u8>>, Box<dyn std::error::Error>> {
    println!("checking geo db...");

    if Path::new("res/geo.mmdb").exists() {
        return maxminddb::Reader::open_readfile("res/geo.mmdb").map_err(|e| e.into());
    }

    println!("missing geo db. downloading...");
    download_resource_file("https://git.io/GeoLite2-City.mmdb", "geo.mmdb")?;
    println!("geo db has been downloaded.");

    Ok(maxminddb::Reader::open_readfile("res/geo.mmdb")?)
}

fn get_whois_db() -> Result<whois_rust::WhoIs, Box<dyn std::error::Error>> {
    println!("checking whois db...");

    if Path::new("res/whois_servers.json").exists() {
        return whois_rust::WhoIs::from_path("res/whois_servers.json").map_err(|e| e.into());
    }

    println!("missing whois db. downloading...");
    download_resource_file(
        "https://raw.githubusercontent.com/FurqanSoftware/node-whois/refs/heads/master/servers.json",
        "whois_servers.json",
    )?;
    println!("whois db has been downloaded.");

    whois_rust::WhoIs::from_path("res/whois_servers.json").map_err(|e| e.into())
}

fn analyse_hop(
    index: u8,
    ip_addr_str: &str,
    multiprog: Arc<MultiProgress>,
    geo_db: Arc<maxminddb::Reader<Vec<u8>>>,
    whois_db: Arc<whois_rust::WhoIs>,
) {
    let mut hop = HopInfo {
        ip_addr: ip_addr_str.parse().unwrap(),
        dns_host: "...".to_string(),
        geo_addr: "...".to_string(),
        whois: WhoIsResult::new_filled("..."),
    };

    let progbar = multiprog.add(ProgressBar::new(1));
    progbar.set_style(ProgressStyle::with_template("{spinner}\n{prefix}: {msg}").unwrap());
    progbar.set_prefix(format!("{:>03}", index));
    update_hop_progress(&hop, &progbar, false);
    progbar.enable_steady_tick(Duration::from_millis(100));

    if ip_addr_str.starts_with("192.168") {
        hop.dns_host = "n/a".to_string();
        hop.geo_addr = "n/a".to_string();
        hop.whois = WhoIsResult::new_filled("n/a");
    } else {
        // reverse DNS lookup
        hop.dns_host = lookup_addr(&hop.ip_addr).unwrap_or("unknown".to_string());
        update_hop_progress(&hop, &progbar, false);

        // geo lookup
        let geo_result = geo_db.lookup(hop.ip_addr).unwrap();
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

        // whois lookup
        hop.whois =
            run_whois_lookup(ip_addr_str, whois_db).unwrap_or(WhoIsResult::new_filled("unknown"));
    }

    // finalise
    update_hop_progress(&hop, &progbar, true);
}

fn run_whois_lookup(
    ip_addr: &str,
    whois_db: Arc<whois_rust::WhoIs>,
) -> Result<WhoIsResult, Box<dyn std::error::Error>> {
    let mut result = WhoIsResult::new_filled("unknown");

    // netname, descr, country, status, source, person, address, created,
    let whois_str = whois_db.lookup(whois_rust::WhoIsLookupOptions::from_string(ip_addr)?)?;

    let regex = Regex::new(r"netname:\s*(?<netname>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.net_name = cap["netname"].to_string();
    }

    let regex = Regex::new(r"descr:\s*(?<desc>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.desc = cap["desc"].to_string();
    }

    let regex = Regex::new(r"country:\s*(?<country>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.country = cap["country"].to_string();
    }

    let regex = Regex::new(r"status:\s*(?<status>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.status = cap["status"].to_string();
    }

    let regex = Regex::new(r"source:\s*(?<source>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.source = cap["source"].to_string();
    }

    let regex = Regex::new(r"person:\s*(?<person>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.person = cap["person"].to_string();
    }

    let regex = Regex::new(r"address:\s*(?<address>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.address = cap["address"].to_string();
    }

    let regex = Regex::new(r"created:\s*(?<created>.*)\s").unwrap();
    if let Some(cap) = regex.captures(&whois_str) {
        result.created = cap["created"].to_string();
    }

    Ok(result)
}

fn update_hop_progress(hop: &HopInfo, progbar: &ProgressBar, finished: bool) {
    if finished {
        progbar.finish_with_message(format!(
            "{}\nhost: {}\ngeo: {}\n{:?}\n\n",
            hop.ip_addr, hop.dns_host, hop.geo_addr, hop.whois
        ));
    } else {
        progbar.set_message(format!(
            "{} - analysing...\nhost: {}\ngeo: {}\n{:?}\n",
            hop.ip_addr, hop.dns_host, hop.geo_addr, hop.whois
        ));
    }
}
