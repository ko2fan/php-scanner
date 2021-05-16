mod util;

use util::event::{Event, Events};
use std::{cell::RefCell, collections::HashMap, error::Error, ffi::OsString, io, rc::Rc, time::SystemTime};
use termion::{event::Key, input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
use tui::{
    backend::TermionBackend,
    style::{Color, Modifier, Style},
    widgets::{Block, Gauge, Paragraph, Wrap, Borders},
    Terminal,
    layout::{Alignment, Constraint, Direction, Layout},
};
use yara::*;
use glob::glob;

use slog::{info, error, debug};
use sloggers::Build;
use sloggers::file::FileLoggerBuilder;

struct App<'r> {
    progress: u16,
    num_lines: u16,
    files_scanned: usize,
    file_list: Vec<OsString>,
    text: Rc<RefCell<String>>,
    results: HashMap<OsString, Vec<Rule<'r>>>,
    rules: Rules,
    logger: slog::Logger,
}

impl<'r> App<'r> {
    fn new(rules: Rules, builder: FileLoggerBuilder) -> App<'r> {
        App {
            progress: 0,
            num_lines: 0,
            files_scanned: 0,
            file_list: Vec::new(),
            text: Rc::new(RefCell::new(String::from("Starting scan\n"))),
            results: HashMap::new(),
            rules: rules,
            logger: builder.build().unwrap(),
        }
    }

    fn update(&mut self) -> Result<(), Box<dyn Error>> {
        self.progress = (100.0 - ((self.file_list.len() - self.files_scanned) as f32 / self.file_list.len() as f32 * 100.0)) as u16;

        if self.files_scanned >= self.file_list.len() {
            self.progress = 100;
            self.text.try_borrow_mut()?.push_str("Scanning finished\n");
            return Ok(());
        }

        
        self.run_scan();
        
        let newlines = self.text.try_borrow()?.matches('\n').collect::<String>();
        if newlines.len() > 5 {
            self.num_lines = newlines.len() as u16 - 5;
        }

        Ok(())
    }

    fn run_scan(&mut self) {
        let file = self.file_list.get(self.files_scanned).expect("Scanned more files than existed");
        let printable_file = file.clone().into_string().expect("Invalid path");
        debug!(self.logger, "Scanning: {}", printable_file);
        self.text.try_borrow_mut().unwrap().push_str(&format!("Scanning {}\n",printable_file));
        let scan_result = self.rules.scan_file(file, 5).unwrap();
        self.results.insert(file.clone(), scan_result);
        self.files_scanned += 1;
    }

    fn build_file_list(&mut self, directory : &str) {
        info!(self.logger, "Scanning: {}", directory);
        let pattern = String::from(directory) + "/**/*.php";
        for entry in glob(pattern.as_str()).expect("Failed to read glob pattern") {
            match entry {
                Ok(path) => self.file_list.push(path.into_os_string()),
                Err(e) => println!("{:?}", e),
            }
        }
    }

    fn log_matches(&self, identifier: &str, file: &OsString) {
        info!(self.logger, "Found {} in {}", identifier, file.to_str().unwrap());
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new("php-scanner")
        .version("0.1")
        .author("David Athay <ko2fan@gmail.com>")
        .about("Scans files for php malware")
        .args_from_usage("<directory> 'Sets the directory to scan'")
        .get_matches();

    let builder = FileLoggerBuilder::new("scan.log");

    let mut compiler = Compiler::new()?;
    compiler.add_rules_file("php.yar")?;
    let rules = compiler.compile_rules()?;

    let mut app = App::new(rules, builder);

    if let Some(dir) = matches.value_of("directory") {
        println!("Scanning: {}", dir);
        app.build_file_list(dir);
    }

    // Terminal initialization
    let stdout = io::stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // start timing
    let timer = SystemTime::now();

    let events = Events::new();

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                [
                    Constraint::Max(2),
                    Constraint::Max(5),
                ].as_ref()
            )
            .split(f.size());

            let label = format!("{}/100", app.progress);
            let gauge = Gauge::default()
                .block(Block::default().title("Scanning progress"))
                .gauge_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::ITALIC),
                )
                .percent(app.progress)
                .label(label)
                .use_unicode(true);
            f.render_widget(gauge, chunks[0]);
            
            let text : String = app.text.borrow().to_string();
            let para = Paragraph::new(text)
                .block(Block::default().title("Files scanned").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black))
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .scroll((app.num_lines, 0));

            f.render_widget(para, chunks[1]);
        })?;

        match events.next()? {
            Event::Input(input) => {
                if input == Key::Char('q') {
                    break;
                }
            }
            Event::Tick => {
                app.update()?;
            }
        }

        if app.progress == 100 {
            break;
        }
    }

    drop(terminal);

    let time_elapsed = timer.elapsed()?;
    let elapsed = format!("{}.{}", time_elapsed.as_secs().to_string(), time_elapsed.as_millis().to_string());

    let mut num_matches = 0;
    for (file, entry) in &app.results {
        num_matches += entry.len();
        for rule in entry {
            app.log_matches(rule.identifier, file);
        }
    }
    
    println!("Scanned {} files and found {} matches in {} seconds", app.files_scanned, num_matches, elapsed);

    Ok(())
}
