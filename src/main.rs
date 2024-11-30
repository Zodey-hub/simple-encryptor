use simple_encryptor::{decrypt, encrypt};
use std::{env, error::Error, fs, io, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <filepath>", args[0]);
        std::process::exit(1);
    }

    let input_file_path = &args[1];
    if input_file_path == "-h" || input_file_path == "--help" {
        eprintln!("Usage: {} <filepath>", args[0]);
        std::process::exit(1);
    }

    let input_file_content = fs::read(input_file_path)?;

    print!("Password: ");
    io::Write::flush(&mut io::stdout())?;

    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;

    if input_file_path.ends_with(".enc") {
        let decrypted_content = decrypt(password.trim().as_bytes(), &input_file_content)?;
        let new_file_path = input_file_path.trim_end_matches(".enc");
        fs::write(new_file_path, decrypted_content)?;
    } else {
        let encrypted_content = encrypt(password.trim().as_bytes(), &input_file_content)?;
        let new_file_path = Path::new(input_file_path).with_extension("enc");
        fs::write(new_file_path, encrypted_content)?;
    }

    Ok(())
}
