use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use tar_core::parse::{Limits, ParseEvent, ParsedEntry, Parser};

use crate::deps::DirFs;

pub fn run(out: &mut impl Write, fs: &impl DirFs, args: &[String]) -> io::Result<()> {
    let (mode, archive) = parse_args(args)?;
    let data = fs.read_bytes(archive)?;
    match mode {
        Mode::List => list_archive(out, &data),
        Mode::Extract => extract_archive(fs, &data),
    }
}

enum Mode {
    List,
    Extract,
}

fn parse_args(args: &[String]) -> io::Result<(Mode, &str)> {
    match args {
        [flag, archive] if flag == "-tf" => Ok((Mode::List, archive)),
        [flag, archive] if flag == "-xf" => Ok((Mode::Extract, archive)),
        _ => Err(io::Error::other("usage: tar <-tf|-xf> <archive.tar>")),
    }
}

fn list_archive(out: &mut impl Write, data: &[u8]) -> io::Result<()> {
    visit_archive(data, |entry, _| writeln!(out, "{}", entry.path_lossy()))
}

fn extract_archive(fs: &impl DirFs, data: &[u8]) -> io::Result<()> {
    visit_archive(data, |entry, body| {
        let path = safe_path(&entry.path)?;
        if entry.is_dir() {
            fs.create_dir_all(&path)?;
            return Ok(());
        }
        if entry.is_file() {
            if let Some(parent) = Path::new(&path).parent() {
                let parent = parent.to_string_lossy();
                if !parent.is_empty() {
                    fs.create_dir_all(&parent)?;
                }
            }
            fs.write_bytes(&path, body)?;
            return Ok(());
        }
        Err(io::Error::other(format!(
            "unsupported tar entry type for {}",
            entry.path_lossy()
        )))
    })
}

fn visit_archive(
    data: &[u8],
    mut visit: impl FnMut(ParsedEntry<'_>, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut parser = Parser::new(Limits {
        max_path_len: Some(4096),
        ..Limits::default()
    });
    let mut offset = 0usize;

    loop {
        match parser
            .parse(&data[offset..])
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            ParseEvent::NeedData { .. } => return Err(io::Error::other("truncated tar archive")),
            ParseEvent::GlobalExtensions { consumed, .. } => {
                offset = offset
                    .checked_add(consumed)
                    .ok_or_else(|| io::Error::other("archive offset overflow"))?;
            }
            ParseEvent::End { consumed } => {
                let _ = offset
                    .checked_add(consumed)
                    .ok_or_else(|| io::Error::other("archive offset overflow"))?;
                return Ok(());
            }
            ParseEvent::SparseEntry { entry, .. } => {
                return Err(io::Error::other(format!(
                    "unsupported sparse tar entry {}",
                    entry.path_lossy()
                )));
            }
            ParseEvent::Entry { consumed, entry } => {
                let start = offset
                    .checked_add(consumed)
                    .ok_or_else(|| io::Error::other("archive offset overflow"))?;
                let size = usize::try_from(entry.size)
                    .map_err(|_| io::Error::other("entry too large to extract"))?;
                let end = start
                    .checked_add(size)
                    .ok_or_else(|| io::Error::other("entry size overflow"))?;
                if end > data.len() {
                    return Err(io::Error::other("truncated tar entry"));
                }
                visit(entry, &data[start..end])?;
                let padded =
                    padded_size(size).ok_or_else(|| io::Error::other("entry padding overflow"))?;
                offset = start
                    .checked_add(padded)
                    .ok_or_else(|| io::Error::other("archive offset overflow"))?;
            }
        }
    }
}

fn padded_size(size: usize) -> Option<usize> {
    size.checked_add(511).map(|n| n / 512 * 512)
}

fn safe_path(raw: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(raw).map_err(|_| io::Error::other("non-utf8 tar path"))?;
    let mut out = PathBuf::new();
    for component in Path::new(text).components() {
        match component {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::other("tar entry escapes current directory"));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(io::Error::other("empty tar path"));
    }
    Ok(out.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::FakeFs;
    use tar_core::EntryType;
    use tar_core::builder::EntryBuilder;

    #[test]
    fn lists_entries() {
        let archive = archive_bytes(&[dir_entry("docs/"), file_entry("docs/readme.txt", b"hello")]);
        let mut out = Vec::new();
        list_archive(&mut out, &archive).unwrap();
        assert_eq!(out, b"docs/\ndocs/readme.txt\n");
    }

    #[test]
    fn extracts_files_and_dirs() {
        let archive = archive_bytes(&[dir_entry("docs/"), file_entry("docs/readme.txt", b"hello")]);
        let fs = FakeFs::new(&[], &[]);
        extract_archive(&fs, &archive).unwrap();
        assert!(fs.has_dir("docs"));
        assert_eq!(
            fs.file("docs/readme.txt").as_deref(),
            Some(b"hello".as_slice())
        );
    }

    #[test]
    fn rejects_traversal() {
        let archive = archive_bytes(&[file_entry("../secret.txt", b"nope")]);
        let fs = FakeFs::new(&[], &[]);
        let err = extract_archive(&fs, &archive).unwrap_err();
        assert!(err.to_string().contains("escapes current directory"));
    }

    #[test]
    fn wrong_args_error() {
        let fs = FakeFs::new(&[], &[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &fs, &[]).is_err());
        assert!(run(&mut out, &fs, &["-cf".into(), "a.tar".into()]).is_err());
    }

    fn archive_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut archive = Vec::new();
        for entry in entries {
            archive.extend_from_slice(entry);
        }
        archive.extend_from_slice(&[0u8; 1024]);
        archive
    }

    fn file_entry(path: &str, body: &[u8]) -> Vec<u8> {
        let mut builder = EntryBuilder::new_ustar();
        builder.path(path.as_bytes());
        builder.mode(0o644).unwrap();
        builder.uid(0).unwrap();
        builder.gid(0).unwrap();
        builder.size(body.len() as u64).unwrap();
        builder.mtime(0).unwrap();
        builder.entry_type(EntryType::Regular);

        let mut out = builder.finish_bytes();
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(512), 0);
        out
    }

    fn dir_entry(path: &str) -> Vec<u8> {
        let mut builder = EntryBuilder::new_ustar();
        builder.path(path.as_bytes());
        builder.mode(0o755).unwrap();
        builder.uid(0).unwrap();
        builder.gid(0).unwrap();
        builder.size(0).unwrap();
        builder.mtime(0).unwrap();
        builder.entry_type(EntryType::Directory);
        builder.finish_bytes()
    }
}
