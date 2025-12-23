use clap::Parser;
use regex::Regex;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    target: String,
}

fn main() {
    let args = Args::parse();

    let mut traceroute = Command::new("traceroute")
        .arg(args.target)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let hop_line_regex = Regex::new(r"^\s*(?<i>\d+).*\((?<a>[\d\.]+)\)").unwrap();

    for line in BufReader::new(traceroute.stdout.take().unwrap()).lines() {
        if let Ok(line) = line {
            if !hop_line_regex.is_match(&line) {
                continue;
            }

            if let Some(parts) = hop_line_regex.captures(&line) {
                let index: u8 = parts["i"].parse().unwrap();
                let ip_addr = parts["a"].to_string();

                thread::spawn(move || {
                    analyse_hop(index, &ip_addr);
                });
            }
        }
    }
}

fn analyse_hop(index: u8, ip_addr: &str) {
    // should print: "hopped over {ip_addr}: analysing..."
    // then line should update to "hopped over {ip_addr}: <the data found>"
}
