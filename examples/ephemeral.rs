//! Create a container, run a command, copy a file out, destroy it.
//!
//! ```sh
//! sudo cargo run --example ephemeral -- \
//!     --data-dir /var/db/blackship --zfs zroot/blackship --release 16.0-CURRENT
//! ```

use blackship::{ContainerSpec, Exec, Host, Network, Stream};
use std::path::PathBuf;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse()?;

    let mut host = Host::new(&args.data_dir);
    if let Some((pool, dataset)) = &args.zfs {
        host = host.with_zfs(pool, dataset);
    }

    let release = host.ensure_release(&args.release)?;
    println!(
        "release {} at {} ({})",
        release.name,
        release.path.display(),
        if release.cloneable {
            "zfs clone"
        } else {
            "copy"
        }
    );

    let name = format!("example-{}", std::process::id());
    let container = host.create(
        &ContainerSpec::new(&name, &release.name)
            .hostname("ephemeral")
            .network(Network::None)
            .label("purpose", "example"),
    )?;
    println!("created {} (jid {})", container.name(), container.jid());

    let run = container.exec(
        Exec::argv(["uname", "-a"])
            .timeout(Duration::from_secs(30))
            .on_output(|stream, bytes| {
                let tag = match stream {
                    Stream::Stdout => "out",
                    Stream::Stderr => "err",
                };
                print!("[{tag}] {}", String::from_utf8_lossy(bytes));
            }),
    )?;
    println!("uname exited {:?} in {:?}", run.exit, run.duration);

    // No rc at boot means no /etc/os-release, so write our own file.
    let wrote = container.exec(Exec::shell(
        "freebsd-version -u > /tmp/userland && hostname >> /tmp/userland",
    ))?;
    if !wrote.exit.success() {
        return Err(format!("writing /tmp/userland failed: {:?}", wrote.exit).into());
    }
    let copied = std::env::temp_dir().join(format!("{name}-userland"));
    container.copy_out("/tmp/userland", &copied)?;
    let userland = std::fs::read_to_string(&copied)?;
    println!(
        "copied /tmp/userland out to {}: {:?}",
        copied.display(),
        userland
    );
    std::fs::remove_file(&copied)?;

    container.destroy()?;
    let leftovers = host
        .containers()?
        .into_iter()
        .filter(|c| c.name == name)
        .count();
    println!("destroyed {name}; leftovers: {leftovers}");
    Ok(())
}

struct Args {
    data_dir: PathBuf,
    zfs: Option<(String, String)>,
    release: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut data_dir = None;
        let mut zfs = None;
        let mut release = None;
        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--data-dir" => data_dir = Some(PathBuf::from(value)),
                "--release" => release = Some(value),
                "--zfs" => {
                    let (pool, dataset) =
                        value.split_once('/').ok_or("--zfs takes pool/dataset")?;
                    zfs = Some((pool.to_string(), dataset.to_string()));
                }
                other => return Err(format!("unknown flag {other}")),
            }
        }
        Ok(Self {
            data_dir: data_dir.ok_or("--data-dir is required")?,
            zfs,
            release: release.ok_or("--release is required")?,
        })
    }
}
