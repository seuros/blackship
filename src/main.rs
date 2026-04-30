fn main() {
    if let Err(e) = blackship::run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
