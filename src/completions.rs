use std::io::{self, Write};

const BASH: &str = include_str!(concat!(env!("OUT_DIR"), "/hako.bash"));
const ZSH: &str = include_str!(concat!(env!("OUT_DIR"), "/hako.zsh"));
const FISH: &str = include_str!(concat!(env!("OUT_DIR"), "/hako.fish"));

pub fn run(out: &mut impl Write, args: &[String]) -> io::Result<()> {
    let shell = args.first().map(String::as_str).unwrap_or("");
    let script = match shell {
        "bash" => BASH,
        "zsh" => ZSH,
        "fish" => FISH,
        _ => {
            return Err(io::Error::other("usage: completions <bash|zsh|fish>"));
        }
    };
    out.write_all(script.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn prints_generated_completions_for_each_shell() {
        for shell in ["bash", "zsh", "fish"] {
            let mut out = Vec::new();
            assert!(run(&mut out, &[shell.into()]).is_ok());
            assert!(out.windows(b"tlsping".len()).any(|w| w == b"tlsping"));
        }
    }

    #[test]
    fn rejects_unknown_shell() {
        let mut out = Vec::new();
        assert!(run(&mut out, &["powershell".into()]).is_err());
        assert!(out.is_empty());
    }
}
