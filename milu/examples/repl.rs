use clap::value_parser;
use easy_error::{ResultExt, Terminator};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::{self, MatchingBracketValidator, Validator};
use rustyline::{Cmd, CompletionType, Config, Context, EditMode, Editor, KeyEvent};
use rustyline_derive::Helper;
use std::borrow::Cow::{self, Borrowed, Owned};
use std::path::PathBuf;
use tokio;

use milu::parser;
use milu::script::Evaluatable;
use milu::script::ScriptContextRef;

#[derive(Helper)]
struct MyHelper {
    completer: FilenameCompleter,
    highlighter: MatchingBracketHighlighter,
    validator: MatchingBracketValidator,
    hinter: HistoryHinter,
    colored_prompt: String,
}

impl Completer for MyHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.completer.complete(line, pos, ctx)
    }
}

impl Hinter for MyHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for MyHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> Cow<'b, str> {
        if default {
            Borrowed(&self.colored_prompt)
        } else {
            Borrowed(prompt)
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize, forced: bool) -> bool {
        self.highlighter.highlight_char(line, pos, forced)
    }
}

impl Validator for MyHelper {
    fn validate(
        &self,
        ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        self.validator.validate(ctx)
    }

    fn validate_while_typing(&self) -> bool {
        self.validator.validate_while_typing()
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
#[tokio::main]
async fn main() -> Result<(), Terminator> {
    let args = clap::Command::new("milu-repl")
        .version(VERSION)
        .arg(
            clap::Arg::new("INPUT")
                .help("filename")
                .value_parser(value_parser!(PathBuf))
                .index(1),
        )
        .get_matches();
    let input = args.get_one("INPUT").map(PathBuf::as_path);
    if let Some(i) = input {
        let buf = std::fs::read(i)?;
        let buf = String::from_utf8(buf)?;
        eval(Default::default(), &buf).await; // Added await
    } else {
        repl().await.context("repl")?; // Added await
    }
    Ok(())
}

async fn repl() -> rustyline::Result<()> {
    // Added async
    #[cfg(target_os = "windows")]
    let is_tty = false;
    #[cfg(not(target_os = "windows"))]
    let is_tty =
        nix::unistd::isatty(std::io::stdin()).map_err(|_e| std::io::Error::last_os_error())?;
    macro_rules! println {
        () => (if(is_tty) {println!("\n")});
        ($($arg:tt)*) => ({if(is_tty) {std::println!($($arg)*);}})
    }

    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    let h = MyHelper {
        completer: FilenameCompleter::new(),
        highlighter: MatchingBracketHighlighter::new(),
        hinter: HistoryHinter {},
        colored_prompt: "".to_owned(),
        validator: MatchingBracketValidator::new(),
    };
    let mut rl = Editor::with_config(config)?;
    rl.set_helper(Some(h));
    rl.bind_sequence(KeyEvent::alt('N'), Cmd::HistorySearchForward);
    rl.bind_sequence(KeyEvent::alt('P'), Cmd::HistorySearchBackward);

    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    println!();
    println!("This is the milu-repl {}", VERSION);
    println!("Use `;;' to end an expression");
    println!("Press Ctrl-D to exit.");
    println!();
    let mut count = 1;
    let mut buf = vec![];
    let global: ScriptContextRef = Default::default();
    loop {
        let p = format!("{}> ", count);
        rl.helper_mut().expect("No helper").colored_prompt = format!("\x1b[1;32m{}\x1b[0m", p);
        let readline = rl.readline(&p);
        match readline {
            Ok(line) => {
                let line = line.trim_end();
                buf.push(line.to_owned());
                if line.ends_with(";;") {
                    let ctx = global.clone();
                    let sbuf = buf.join(" ");
                    eval(ctx, &sbuf).await; // Added await
                    if let Err(e) = rl.add_history_entry(&sbuf) {
                        eprintln!("Failed to add history entry: {}", e);
                    }
                    count += 1;
                    buf.clear();
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Interrupted");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("Ctrl-D");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }

    rl.append_history("history.txt")
}

async fn eval(ctx: ScriptContextRef, str: &str) -> bool {
    // Added async
    let val_parse_result = parser::parse(str); // Renamed to avoid conflict
    if let Err(e) = val_parse_result {
        eprintln!("parser error: {}", e);
        return false;
    }
    let parsed_val = val_parse_result.unwrap(); // Renamed to avoid conflict
    let typ_result = parsed_val.type_of(ctx.clone()).await; // Renamed to avoid conflict
    if let Err(e) = typ_result {
        eprintln!("type inference error: {}", e);
        return false;
    }
    let eval_result = parsed_val.value_of(ctx).await; // Added await, renamed
    if let Err(e) = eval_result {
        eprintln!("eval error: {}", e);
        return false;
    }
    let final_val = eval_result.unwrap(); // Renamed to avoid conflict
    let final_typ = typ_result.unwrap(); // Renamed to avoid conflict
    println!("{} : {}", final_val, final_typ);
    true
}
