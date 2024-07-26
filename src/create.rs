use crate::cli::CreateArgs;

/// Create a new encrypted file in the given path.
/// Do nothing and return error if the file already exists.
///
/// # Examples
/// ```no_run
/// encrypted_file_manager::create(CreateArgs { file: "example.encrypted".into() })
/// ```
pub fn create(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("Password: ")?;
    todo!()
}
