use std::{collections::HashMap, error::Error, ffi::OsString, sync::Arc, thread, time::SystemTime};
use yara::*;
use glob::glob;

use slog::{Logger, debug, error, info};
use sloggers::Build;
use sloggers::file::FileLoggerBuilder;

fn log_matches(logger: &Logger, identifier: &str, file: &OsString) {
    info!(logger, "Found {} in {}", identifier, file.to_str().unwrap());
}

fn build_file_list(directory : &str) -> Vec<OsString> {
    let mut result = Vec::new();
    let pattern = String::from(directory) + "/**/*.php";
    for entry in glob(pattern.as_str()).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => result.push(path.into_os_string()),
            Err(e) => println!("{:?}", e),
        }
    }

    result
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new("php-scanner")
        .version("0.2")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Scans files for php malware")
        .args_from_usage("<directory> 'Sets the directory to scan'")
        .get_matches();

    let builder = FileLoggerBuilder::new("scan.log");
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

    // start timing
    let timer = SystemTime::now();

    let mut progress = 0;

    loop {

        let num_threads;
        let files_left = files_list.len() - files_scanned;
        if files_left > 5 {
            num_threads = 5;
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
            let res = rules.scan_file(&file, 5);
            match res {
                Ok(f)=> {
                    children.push(thread::spawn(move || -> (OsString, Vec<Rule>) {
                        (file.clone(), f)
                    }));
                },
                Err(e)=> {
                    println!("Unable to scan {:?} {:?}", file, e);
                    info!(logger, "Unable to scan {:?} {:?}", file, e);
                }
            }
        }

        for c in children {
            let result = c.join().unwrap();
            results.insert(result.0, result.1);
            files_scanned += 1;
        }

        progress = (100.0 - ((files_list.len() - files_scanned) as f32 / files_list.len() as f32 * 100.0)) as u16;

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

    Ok(())
}
