pub trait Fs {
    fn read(&self, path: &str) -> std::io::Result<String>;
    fn write(&self, path: &str, content: &str) -> std::io::Result<()>;
    fn is_file(&self, path: &str) -> bool;
}

#[derive(Clone, Copy)]
pub struct SystemFs;

impl Fs for SystemFs {
    fn read(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
    fn write(&self, path: &str, content: &str) -> std::io::Result<()> {
        std::fs::write(path, content)
    }
    fn is_file(&self, path: &str) -> bool {
        std::path::Path::new(path).is_file()
    }
}

pub trait DirFs: Fs {
    fn read_bytes(&self, path: &str) -> std::io::Result<Vec<u8>>;
    fn write_bytes(&self, path: &str, content: &[u8]) -> std::io::Result<()>;
    fn create_dir_all(&self, path: &str) -> std::io::Result<()>;
    fn is_dir(&self, path: &str) -> bool;
    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>>;
}

impl DirFs for SystemFs {
    fn read_bytes(&self, path: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn write_bytes(&self, path: &str, content: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, content)
    }
    fn create_dir_all(&self, path: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
    fn is_dir(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
    }
    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
        let mut entries: Vec<String> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        Ok(entries)
    }
}
