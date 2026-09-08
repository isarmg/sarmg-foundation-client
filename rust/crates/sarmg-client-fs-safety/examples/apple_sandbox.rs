#[cfg(target_vendor = "apple")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sarmg_client_fs_safety::{
        AtomicFile, EntryName, PrivateDirectory, RelativePath, validate_directory_path,
    };
    use std::{fs, path::PathBuf};
    let root = PathBuf::from(std::env::args_os().nth(1).expect("sandbox directory"));
    // Prove this process really cannot inspect or list the outside ancestor.
    assert!(fs::symlink_metadata(root.parent().unwrap()).is_err());
    assert!(fs::File::open(root.parent().unwrap()).is_err());
    validate_directory_path(&root)?;
    let state = PrivateDirectory::create(root.join("state"))?;
    let key = RelativePath::new("state.json")?;
    AtomicFile::replace(&state, &key, b"preserved")?;
    assert_eq!(
        state.read_bounded(&EntryName::new("state.json")?, 100)?,
        b"preserved"
    );
    std::os::unix::fs::symlink(root.join("state"), root.join("alias"))?;
    assert!(PrivateDirectory::open_existing(root.join("alias")).is_err());
    assert!(validate_directory_path(&root.join("alias")).is_err());
    assert!(validate_directory_path(&root.join("alias/child")).is_err());
    println!("Apple sandbox storage and symlink rejection passed");
    Ok(())
}
#[cfg(not(target_vendor = "apple"))]
fn main() {}
