use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use regex::Regex;
use std::{
    io::{BufRead, BufReader},
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
}

fn analyse_hop(index: u8, ip_addr: &str, multiprog: Arc<MultiProgress>) {
    let progbar = multiprog.add(ProgressBar::new(1));
    progbar.set_style(ProgressStyle::with_template("{prefix:>3}: {msg} {spinner}").unwrap());
    progbar.set_prefix(format!("{}", index));
    progbar.set_message(format!("{:<15} - analysing...", ip_addr));
    progbar.enable_steady_tick(Duration::from_millis(100));

    // todo
    thread::sleep(Duration::from_secs(2));

    progbar.finish_with_message(format!("{:<15} - someserver.net (earth)", ip_addr));
}
