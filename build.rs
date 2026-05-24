use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

use clap::{Arg, ArgAction, Command, ValueHint};
use clap_complete::{Generator, generate};

include!("./commands.rs");

fn arg_value(name: &'static str, value: &'static str) -> Arg {
    Arg::new(name).value_name(value)
}

fn arg_file(name: &'static str, value: &'static str) -> Arg {
    Arg::new(name)
        .value_name(value)
        .value_hint(ValueHint::FilePath)
}

fn arg_short_flag(name: &'static str, short: char, help: &'static str) -> Arg {
    Arg::new(name)
        .short(short)
        .help(help)
        .action(ArgAction::SetTrue)
}

fn arg_long_flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}

fn arg_short_value(
    name: &'static str,
    short: char,
    value: &'static str,
    help: &'static str,
) -> Arg {
    Arg::new(name)
        .short(short)
        .value_name(value)
        .help(help)
        .num_args(1)
}

fn arg_long_value(
    name: &'static str,
    long: &'static str,
    value: &'static str,
    help: &'static str,
) -> Arg {
    Arg::new(name)
        .long(long)
        .value_name(value)
        .help(help)
        .num_args(1)
}

fn arg_short_long_value(
    name: &'static str,
    short: char,
    long: &'static str,
    value: &'static str,
    help: &'static str,
) -> Arg {
    Arg::new(name)
        .short(short)
        .long(long)
        .value_name(value)
        .help(help)
        .num_args(1)
}

fn cli() -> Command {
    macro_rules! clap_command {
        ($cmd:ident, $name:ident, $desc:expr, [$($arg:expr),* $(,)?], $run:block) => {{
            $cmd = $cmd.subcommand(Command::new(stringify!($name))
                .about($desc)
                .disable_help_flag(true)
                $(.arg($arg))*);
        }};
    }

    let mut cmd = Command::new("hako")
        .about("tiny toybox")
        .disable_help_flag(true)
        .disable_help_subcommand(true);
    hako_commands!(clap_command, out, rest, cmd);
    cmd
}

fn completion(shell: impl Generator) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cmd = cli();
    generate(shell, &mut cmd, "hako", &mut out);
    out
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if fs::read(path).is_ok_and(|old| old == contents) {
        return Ok(());
    }
    fs::write(path, contents)?;
    Ok(())
}

fn render_man(cmd: Command) -> Result<Vec<u8>, std::io::Error> {
    let mut out = Vec::new();
    clap_mangen::Man::new(cmd).render(&mut out)?;
    Ok(out)
}

fn write_man_pages(man_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let man1 = man_dir.join("man1");
    fs::create_dir_all(&man1)?;

    let mut generated = BTreeSet::new();
    let mut cmd = cli();
    cmd.build();

    generated.insert(PathBuf::from("man1/hako.1"));
    write_if_changed(&man1.join("hako.1"), &render_man(cmd.clone())?)?;

    for subcmd in cmd.get_subcommands().cloned() {
        let file = format!(
            "{}.1",
            subcmd.get_display_name().unwrap_or(subcmd.get_name())
        );
        generated.insert(PathBuf::from("man1").join(&file));
        write_if_changed(&man1.join(file), &render_man(subcmd)?)?;
    }

    for entry in fs::read_dir(man_dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "1") {
            fs::remove_file(path)?;
        }
    }

    for entry in fs::read_dir(&man1)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "1") {
            let rel = PathBuf::from("man1").join(path.file_name().ok_or("missing file name")?);
            if !generated.contains(&rel) {
                fs::remove_file(path)?;
            }
        }
    }

    Ok(())
}

fn write_generated_files(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let names = cli()
        .get_subcommands()
        .map(|cmd| format!("{:?}", cmd.get_name()))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(out_dir.join("command-names.rs"), format!("[{names}]"))?;

    fs::write(
        out_dir.join("hako.bash"),
        completion(clap_complete::shells::Bash),
    )?;
    fs::write(
        out_dir.join("hako.zsh"),
        completion(clap_complete::shells::Zsh),
    )?;
    fs::write(
        out_dir.join("hako.fish"),
        completion(clap_complete::shells::Fish),
    )?;

    write_man_pages(Path::new("man"))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=commands.rs");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set by Cargo")?);
    write_generated_files(&out_dir)?;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(out_dir.join("httpserver-cert.der"), cert.cert.der())?;
    fs::write(
        out_dir.join("httpserver-key.der"),
        cert.key_pair.serialize_der(),
    )?;
    Ok(())
}
