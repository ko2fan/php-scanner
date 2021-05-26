use std::{collections::HashMap, error::Error, ffi::OsString, fs::OpenOptions, sync::Arc, thread, time::SystemTime};
use yara::*;
use walkdir::{WalkDir, DirEntry};

use slog::{Logger, info};
use sloggers::Build;
use sloggers::file::FileLoggerBuilder;

fn log_matches(logger: &Logger, identifier: &str, file: &OsString) {
    info!(logger, "Found {} in {}", identifier, file.to_str().unwrap());
}

fn is_php_file(entry: &DirEntry) -> bool {
    entry.file_name()
         .to_str()
         .map(|s| s.ends_with(".php"))
         .unwrap_or(false)
}


fn build_file_list(directory : &str) -> Vec<OsString> {
    let mut result = Vec::new();
    for e in WalkDir::new(directory).into_iter().filter_entry(|e| is_php_file(e) || e.file_type().is_dir()) {
        let e = match e {
            Ok(e) => e,
            Err(_) => continue,
        };
        if e.metadata().unwrap().is_file() {
            result.push(e.path().to_path_buf().into_os_string());
        }
    }

    result
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new("php-scanner")
        .version("0.4.0")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Scans files for php malware")
        .args_from_usage("<directory> 'Sets the directory to scan'
        -c [threads] 'Set the maximum number of threads to use'
        -t [timeout] 'Set the timeout on scanning each file'")
        .get_matches();

    let logpath;
    if OpenOptions::new().write(true).create(true).open("/var/log/scan.log").is_ok() {
        logpath = "/var/log/scan.log";
    } else {
        logpath = "scan.log";
    }

    let builder = FileLoggerBuilder::new(logpath);
    let logger = builder.build().unwrap();

    let mut compiler = Compiler::new()?;
    match compiler.add_rules_file("php.yar") {
        Ok(()) => (),
        Err(_) => compiler.add_rules_file("/usr/share/php-scanner/php.yar")?,
    }
    let rules = Arc::new(compiler.compile_rules()?);

    let mut files_list = Vec::new();
    let mut files_scanned = 0;

    let mut results = HashMap::new();

    if let Some(dir) = matches.value_of("directory") {
        println!("Scanning: {}", dir);
        info!(logger, "Scanning: {}", dir);
        files_list = build_file_list(dir);
    }

    let max_threads;
    if let Some(threads) = matches.value_of("c") {
        max_threads = threads.parse::<usize>().unwrap_or(5);
    } else {
        max_threads = 5;
    }

    let timeout;
    if let Some(t) = matches.value_of("t") {
        timeout = t.parse::<u16>().unwrap_or(5);
    } else {
        timeout = 5;
    }

    info!(logger, "Using max of {} threads, default is 5", max_threads);
    info!(logger, "Using timeout of {} seconds. Default is 5 seconds", timeout);

    // start timing
    let timer = SystemTime::now();

    let mut progress;

    loop {

        let num_threads;
        let files_left = files_list.len() - files_scanned;
        if files_left > 5 {
            num_threads = max_threads;
        } else if files_left > 0 {
            num_threads = files_left;
        } else {
            break;
        }

        let mut children = Vec::new();
        let mut files_to_scan: Vec<OsString> = Vec::new();

        files_to_scan.extend_from_slice(&files_list[files_scanned..files_scanned+num_threads]);

        for t in 0..num_threads {
            let file = files_to_scan[t].clone();
            let rules = rules.clone();
            let log = logger.clone();
            children.push(thread::spawn(move || -> Option<(OsString, Vec<Rule>)> {
                match rules.scan_file(&file, timeout) {
                    Ok(f) => Some((file.clone(), f)),
                    Err(e)=> {
                        println!("Unable to scan {:?} {:?}", file, e);
                        info!(log, "Unable to scan {:?} {:?}", file, e);
                        None
                    }
                }
            }));
        }

        for c in children {
            let result = c.join().unwrap();
            if let Some(result) = result {
                results.insert(result.0, result.1);
            }
            files_scanned += 1;
        }

        progress = (100.0 - ((files_list.len() - files_scanned) as f32 / files_list.len() as f32 * 100.0)) as u16;

        println!("{}% complete", progress);

        if progress == 100 {
            break;
        }
    }

    let time_elapsed = timer.elapsed()?;
    let elapsed = format!("{}.{}", time_elapsed.as_secs().to_string(), time_elapsed.as_millis().to_string());

    let mut num_matches = 0;
    for (file, entry) in &results {
        num_matches += entry.len();
        for rule in entry {
            log_matches(&logger, rule.identifier, file);
        }
    }
    
    println!("Scanned {} files and found {} matches in {} seconds", files_scanned, num_matches, elapsed);
    info!(logger, "Scanned {} files and found {} matches in {} seconds", files_scanned, num_matches, elapsed);

    Ok(())
}
