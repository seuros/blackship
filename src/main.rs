fn main() {
    if let Err(e) = blackship::run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
