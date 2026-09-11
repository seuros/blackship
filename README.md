# Blackship

A FreeBSD jail orchestrator with TOML configuration, dependency management, state machine lifecycle control, and ZFS integration.

## Features

- **Declarative Configuration**: Define jails in TOML with dependencies, networking, hooks, and resource limits
- **Dependency Management**: Real dependency-graph traversal for start/stop ordering; target jails by name, unambiguous prefix, tag, or ALL
- **State Machine Lifecycle**: Clean state transitions, devfs mounted per jail, /etc/rc boot and /etc/rc.shutdown on stop
- **Hot Updates (EVA)**: `blackship eva` diffs the config against running jails and applies parameter, rctl, and cpuset changes live via jail_set(JAIL_UPDATE) -- no restart, with drift warnings for changes that need one
- **VNET Networking**: epair (if_bridge) and native netgraph (ng_bridge) backends, named networks with automatic host gateway wiring, deterministic MAC addresses
- **Instant Provisioning**: releases bootstrap into datasets with a @pristine snapshot; jail roots are zfs clones, created in under a second
- **Jailfile Builds with Layer Cache**: every RUN/COPY is snapshotted; rebuilds resume from the longest cached prefix like a Docker layer cache
- **blackship commit**: freeze a configured jail into a reusable release (zero-copy snapshot + clone + promote)
- **pkgbase Bootstrap**: FreeBSD 16+ userlands from fingerprint-verified base package repos (automatic; --pkgbase opts in earlier)
- **Resource Limits**: rctl (memory, pcpu, maxproc, openfiles, ...) plus cpuset pinning with least-loaded core allocation
- **Health Checks & Supervision**: HTTP, TCP, and command checks; warden auto-restart; optional dead-man ping to healthchecks.io/Uptime Kuma
- **Migration & Import**: zfs send | ssh zfs receive between hosts with the jail definition staged inside the dataset; import from iocage, ezjail, or plain rootfs archives
- **Stats**: per-jail CPU, RSS, and process counts from jls/ps libxo JSON
- **Port Forwarding**: PF-based port exposure with source IP binding
- **Shell Completion**: Bash, Zsh, and Fish completions

## Requirements

- FreeBSD 15.0+ with jail support
- ZFS (optional, for snapshots/clones)
- PF (optional, for port forwarding)

Building from source also needs a C compiler and the base system headers:
the ioctl request codes and netgraph message constants are read out of
`/usr/include` at build time rather than hardcoded. Both ship with a
default FreeBSD install. The crate does not build on other operating
systems.

## Installation

```sh
# Install from crates.io
cargo install blackship

# Or download precompiled binary from releases
fetch https://github.com/seuros/blackship/releases/latest/download/blackship-freebsd-amd64.tar.gz
tar xzf blackship-freebsd-amd64.tar.gz
sudo mv blackship /usr/local/bin/

# Install shell completion (optional)
blackship completion bash > /usr/local/etc/bash_completion.d/blackship
blackship completion zsh > /usr/local/share/zsh/site-functions/_blackship
blackship completion fish > ~/.config/fish/completions/blackship.fish
```

## Default Paths

Blackship uses XDG-compliant user directories by default:

| Path | Default | Environment Override |
|------|---------|---------------------|
| `data_dir` | `~/.local/share/blackship` | `XDG_DATA_HOME` |
| `releases_dir` | `~/.local/share/blackship/releases` | - |
| `cache_dir` | `~/.cache/blackship` | `XDG_CACHE_HOME` |

These defaults allow running blackship without root for most operations. Override in `blackship.toml` for system-wide paths:

```toml
[config]
data_dir = "/var/blackship"
releases_dir = "/var/blackship/releases"
cache_dir = "/var/blackship/cache"
```

> **Note:** While paths are user-writable by default, `bootstrap` extraction requires root privileges because FreeBSD base archives contain root-owned files with special permissions (setuid binaries, etc.). Blackship will re-exec through `sudo` or `doas` if needed.

## Quick Start

### 1. Initialize Jailfile

```sh
# Create a Jailfile in current directory
blackship init

# Create with specific FreeBSD release
blackship init --release 15.1-RELEASE

# TOML format instead of Dockerfile-like
blackship init --toml
```

### 2. Initialize Armada Configuration

Create `blackship.toml`:

```toml
[config]
# Paths default to XDG directories (~/.local/share/blackship, ~/.cache/blackship)
# Uncomment to use system-wide paths:
# data_dir = "/var/blackship"
zfs_enabled = true
zpool = "zroot"
dataset = "blackship"

[[jails]]
name = "web"
release = "15.1-RELEASE"
hostname = "web.local"

[jails.network]
vnet = true
networks = ["default"]
bridge = "blackship0"
ip = "10.0.1.10"
gateway = "10.0.1.1"
```

Or use `blackship armada init` to generate a template.

### 3. Bootstrap a Release

```sh
# Download and extract FreeBSD base (requires root for extraction).
# With ZFS enabled the release lands in its own dataset with a @pristine
# snapshot, so jails clone-provision from it instantly.
blackship bootstrap 15.1-RELEASE

# FreeBSD 16 has no dist sets, so pkgbase is used automatically
# (16.0 is still -CURRENT; --pkgbase opts in on older branches)
blackship bootstrap 16.0-CURRENT

# List available releases
blackship releases
```

### 4. Create Network

```sh
# if_bridge network with gateway on the bridge (requires root)
blackship network create default --subnet 10.0.1.0/24 --gateway 10.0.1.1 --bridge blackship0

# netgraph network: ng_bridge plus a host-side gateway eiface, wired
# automatically; jails attached to it inherit the netgraph backend
blackship network create default --subnet 10.0.1.0/24 --backend netgraph --bridge ngbridge0
```

Networks persist across reboots: `blackship setup` (run by the warden rc
script at boot) recreates missing bridges and gateway interfaces. If PF is
not running yet, `blackship setup --enable-pf` writes a minimal pf.conf with
the blackship anchors, sets `pf_enable=YES`, and starts it.

Named networks created this way can be referenced from `blackship.toml` with
`[jails.network] networks = ["default"]`, and the same network can be used by
ephemeral jails with `blackship run --network default`.

### 5. Start Jails

```sh
# Start a specific jail
blackship up web

# Start all jails
blackship up --all

# Dry run (show what would happen)
blackship up --all --dry-run
```

### 6. Interact with Jails

```sh
# Open console
blackship console web

# Execute command
blackship exec web -- pkg install -y nginx

# Check status
blackship ps
blackship ps --json
```

## Configuration Reference

### Global Config

```toml
[config]
# All paths are optional - defaults to XDG directories
data_dir = "~/.local/share/blackship"      # Base data directory (default)
releases_dir = "~/.local/share/blackship/releases"  # FreeBSD releases (default)
cache_dir = "~/.cache/blackship"           # Download cache (default)
mirror_url = "https://download.freebsd.org"  # FreeBSD mirror
zfs_enabled = true                         # Enable ZFS features
zpool = "zroot"                            # ZFS pool name
dataset = "blackship"                      # Base dataset name
monitor_ping_url = "https://hc-ping.com/…"  # Dead-man ping from the supervisor (optional)
```

With ZFS enabled the jails dataset is mounted at `data_dir/jails`, so jail
roots live at the same paths whether or not they are datasets.

### Jail Definition

```toml
[[jails]]
name = "myapp"                        # Jail name (required)
release = "15.1-RELEASE"              # Base release (clone-provisioned when @pristine exists)
path = "/jails/myapp"                 # Custom path (optional; default data_dir/jails/<name>)
hostname = "myapp.local"              # Hostname
depends_on = ["database"]             # Dependencies
tags = ["web", "prod"]                # Tags for group targeting (blackship down prod)
devfs_ruleset = 4                     # devfs ruleset (default 4; 0 disables devfs)
init = true                           # Run /etc/rc at start, /etc/rc.shutdown at stop (default)

[jails.resources]
memory = "1g"                         # rctl memoryuse:deny
cpu = "150"                           # rctl pcpu:deny (percent)
maxproc = 200                         # rctl maxproc:deny
cores = 2                             # Pin to N least-loaded CPUs
# cpuset = "0,1"                      # Or pin to an explicit CPU list

[jails.network]
vnet = true                           # Enable VNET
networks = ["default"]                # Named networks to attach to
bridge = "blackship0"                 # Optional if runtime network state defines a bridge
ip = "10.0.1.10"                      # Static IP, or omit for auto-assignment
gateway = "10.0.1.1"                  # Optional if resolved from named network
mac_address = "02:00:00:00:00:01"     # Static MAC (default: deterministic from jail name)
# backend = "netgraph"                # Inherited from the named network when omitted

[jails.network.dns]
nameservers = ["8.8.8.8", "8.8.4.4"]  # DNS servers
mode = "custom"                        # custom or inherit

[jails.healthcheck]
enabled = true

[[jails.healthcheck.checks]]
name = "http"
command = "curl -sf http://localhost:80/health"
target = "jail"
interval = 30
timeout = 10
retries = 3

[[jails.healthcheck.checks]]
name = "process"
command = "pgrep nginx"
target = "jail"

[[jails.hooks]]
phase = "post_start"                  # pre_create, post_create, pre_start, post_start,
target = "jail"                       # pre_stop, post_stop, pre_eva, post_eva
command = "/etc/rc.d/nginx start"
on_failure = "abort"                  # abort or continue

[[jails.hooks]]
phase = "pre_stop"
target = "jail"
command = "/etc/rc.d/nginx stop"
on_failure = "continue"
```

## Commands

### Lifecycle

| Command | Description |
|---------|-------------|
| `blackship up [target] [--all] [--dry-run]` | Start jail(s) with dependencies |
| `blackship down [target] [--all] [--dry-run]` | Stop jail(s) in reverse order |
| `blackship restart [target] [--all] [--dry-run]` | Restart jail(s) |
| `blackship eva [target] [--all] [--dry-run]` | Hot-update running jail(s) to match the config, no restart |

Targets accept a jail name, an unambiguous prefix, a tag (from `tags = [...]`
in the jail definition), or `ALL`.

`eva` recomputes each jail's parameters from the config, diffs them against
the live values from jls, and applies only the changes in one
jail_set(JAIL_UPDATE) call, then replaces rctl rules and re-pins the cpuset.
`path`, `vnet`, and IP addresses cannot change live: drift on those is
reported as a restart-required warning and skipped. Not-running jails are
skipped. `--dry-run` prints the diff without touching anything.
| `blackship ps [--json]` | List jail status |
| `blackship check` | Validate configuration |
| `blackship setup [--enable-pf]` | Reapply networks and PF anchors; --enable-pf turns PF on |
| `blackship cleanup <jail> [--force]` | Clean up failed jail resources |
| `blackship init [-f file] [--release] [--toml]` | Create a new Jailfile |

### Console & Execution

| Command | Description |
|---------|-------------|
| `blackship console <jail> [-u user]` | Open interactive shell |
| `blackship exec <jail> [-u user] [-w dir] [-e K=V] -- <cmd>` | Execute command in jail |
| `blackship run --name <n> --release <r> [--network <net>] [-d] -- <cmd>` | Run ephemeral jail (auto-cleanup unless -d) |

### File Operations

| Command | Description |
|---------|-------------|
| `blackship cp <src> <dest>` | Copy files (use `jail:path` for jail paths) |
| `blackship rm <jails...> [-f] [--volumes]` | Remove/destroy jails |

### Bootstrap & Releases

| Command | Description |
|---------|-------------|
| `blackship bootstrap <release> [-f] [-a archives] [--pkgbase]` | Download FreeBSD release (pkgbase automatic for 16+) |
| `blackship releases [list\|delete\|verify] [--json]` | Manage releases |

### Networking

| Command | Description |
|---------|-------------|
| `blackship network create <name> -s <subnet> [-g gw] [-b bridge] [--backend epair\|netgraph]` | Create network (requires root) |
| `blackship network destroy <name> [--force]` | Destroy network (requires root) |
| `blackship network list` | List Blackship-managed networks |
| `blackship expose <jail> -p <port> [-I bind-ip] [--proto tcp\|udp]` | Expose port |
| `blackship ports [jail]` | List exposed ports |

### Snapshots & Clones (requires ZFS)

| Command | Description |
|---------|-------------|
| `blackship snapshot create <jail> [name]` | Create snapshot |
| `blackship snapshot list <jail> [--json]` | List snapshots |
| `blackship snapshot rollback <jail> <snap> [--force]` | Rollback to snapshot |
| `blackship snapshot delete <jail> <snap>` | Delete snapshot |
| `blackship clone <jail>@<snap> <newname>` | Clone from snapshot |
| `blackship commit <jail> <release>` | Freeze a jail into a reusable release (zero-copy) |

Snapshots (and commits) stage the jail definition at `.blackship/` inside
the dataset, so `zfs send` carries everything needed to rebuild the jail.

### Export & Import

| Command | Description |
|---------|-------------|
| `blackship export <jail> [-o file] [--zfs-send]` | Export to archive |
| `blackship import <file> [-n name] [--force]` | Import from archive |
| `blackship import <file> --from iocage\|ezjail\|rootfs\|auto [-n name]` | Import from another jail manager |
| `blackship migrate <jail> user@host [--remote-dataset ds]` | Move a jail to another host over ssh |

### Build System

| Command | Description |
|---------|-------------|
| `blackship build [-f Jailfile] [-n name] [--build-arg K=V] [--dry-run]` | Build from Jailfile (ZFS layer cache: unchanged steps print CACHED) |
| `blackship template list` | List templates |
| `blackship template inspect <file>` | Show Jailfile details |
| `blackship template validate <file>` | Validate Jailfile |

### Health & Monitoring

| Command | Description |
|---------|-------------|
| `blackship health [jail] [-w] [-i interval] [--json]` | Health check status |
| `blackship stats [jail] [--json]` | Per-jail CPU, RSS, and process counts |
| `blackship supervise` | Start Warden supervisor for auto-restart |
| `blackship logs <jail> [-f] [-n lines]` | Tail jail logs |

### Armada (Multi-Jail Orchestration)

| Command | Description |
|---------|-------------|
| `blackship armada init [-f file]` | Create a new blackship.toml |
| `blackship armada up [-d] [jails...]` | Start all jails |
| `blackship armada down [jails...]` | Stop all jails |
| `blackship armada build [jails...]` | Build jails from Jailfiles |
| `blackship armada ps [--json]` | Show status of all jails |
| `blackship armada config [--show]` | Validate and show configuration |

#### Config File Merging

Armada supports merging multiple config files (later files override earlier):

```sh
# Merge base config with production overrides
blackship armada -f base.toml -f prod.toml up

# Merge multiple files
blackship armada -f base.toml -f secrets.toml -f local.toml up
```

#### Jailfile References

Jails in `blackship.toml` can reference Jailfiles for building:

```toml
[[jails]]
name = "web"
build = "./web"              # Directory containing Jailfile
depends_on = ["db"]

[[jails]]
name = "api"
jailfile = "./custom/Api.jailfile"  # Explicit Jailfile path
```

### Shell Completion

| Command | Description |
|---------|-------------|
| `blackship completion bash\|zsh\|fish` | Generate shell completion |

## Jailfile Format

Jailfiles define reproducible jail builds, similar to Dockerfiles:

```dockerfile
# Jailfile
FROM 15.1-RELEASE

# Labels (metadata)
LABEL name=nginx-jail version=1.0

# Build arguments
ARG NGINX_VERSION=1.24

# Environment variables
ENV NGINX_VERSION=${NGINX_VERSION}

# Run commands (executed via jexec)
RUN pkg install -y nginx-${NGINX_VERSION}
RUN sysrc nginx_enable=YES

# Copy files from build context
COPY nginx.conf /usr/local/etc/nginx/nginx.conf
COPY html/ /usr/local/www/html/

# Set working directory
WORKDIR /usr/local/www

# Expose ports (documentation)
EXPOSE 80/tcp
EXPOSE 443/tcp

# Default command
CMD /usr/local/sbin/nginx -g 'daemon off;'
```

### TOML Format (Alternative)

```toml
# Jailfile.toml
[metadata]
name = "nginx-jail"
version = "1.0"

from = "15.1-RELEASE"

[[args]]
name = "NGINX_VERSION"
default = "1.24"

[[instructions]]
type = "run"
command = "pkg install -y nginx"

[[instructions]]
type = "copy"
src = "nginx.conf"
dest = "/usr/local/etc/nginx/nginx.conf"

[[expose]]
port = 80
protocol = "tcp"

cmd = "/usr/local/sbin/nginx -g 'daemon off;'"
```

### Build Commands

```sh
# Basic build
blackship build -f Jailfile -n myjail

# With build arguments
blackship build -f Jailfile -n myjail --build-arg NGINX_VERSION=1.26

# Dry run
blackship build -f Jailfile --dry-run
```

## ZFS Integration

ZFS is what makes jails cheap. With `zfs_enabled = true`:

1. Releases bootstrap into their own dataset and get a `@pristine` snapshot
2. Jail roots are `zfs clone`s of that snapshot, so creation is near-instant
   and jails share the base blocks instead of copying them
3. Jailfile builds snapshot each step, giving rebuilds a layer cache
4. `blackship commit` freezes a jail back into a reusable release
5. Snapshots carry the jail's own definition, and send/receive moves jails
   between hosts

The jails dataset is mounted at `data_dir/jails`, so a jail root is at the
same path whether or not it is a dataset. Without ZFS everything still works,
but each jail is a full copy of the release (Blackship refuses the copy if the
filesystem cannot take it).

### Instant provisioning and commit

```sh
# Bootstrap once: extracts to a dataset, snapshots it @pristine
blackship bootstrap 15.1-RELEASE

# Jails clone from it: sub-second, and nearly free on disk
blackship up web

# Configure a jail, then freeze it into a reusable release
blackship build -f Jailfile -n runner
blackship commit runner runner-golden

# Everything cloned from it starts pre-configured
blackship run --name ci-1 --release runner-golden -- ./run-tests.sh
```

### Build layer cache

Every `RUN` and `COPY` is snapshotted as `bs-layer-<n>-<hash>`, keyed by a
rolling hash of the instructions before it, the build arguments, the base
release, and the contents of anything copied in. A rebuild rolls back to the
longest cached prefix and continues from there:

```
$ blackship build -f runner/Jailfile -n runner
CACHED steps 1-5 (layer bs-layer-4-a1aadc5d826c)
Build complete! Jail root: /var/blackship/jails/armada-runner
```

Change a line in the Jailfile and only that step and everything after it
re-runs, exactly like a Docker layer cache.

### Snapshot Workflow

Snapshots stage the jail's definition (and its Jailfile, when known) at
`.blackship/` inside the dataset first, so a `zfs send` of the snapshot
carries everything needed to rebuild the jail elsewhere.

```sh
# Create snapshot before changes
blackship snapshot create web pre-update

# Make changes
blackship exec web -- pkg upgrade -y

# If something breaks, rollback
blackship down web
blackship snapshot rollback web pre-update --force
blackship up web

# Clone for testing
blackship clone web@pre-update web-test
```

### Export/Import with ZFS

```sh
# Fast export using ZFS send
blackship export web -o web-backup.zfs --zfs-send

# Standard tar.zst export
blackship export web -o web-backup.tar.zst

# Import (auto-detects format)
blackship import web-backup.tar.zst --name web-restored

# Import from another jail manager
blackship import old-jail.zip --from iocage --name legacy

# Move a stopped jail to another host over ssh
blackship migrate web seuros@otherbox
```

## Networking

Every VNET jail gets its own network stack and one interface plugged into a
host bridge. Blackship implements that two ways, and a *named network* picks
which one:

| | `epair` (default) | `netgraph` |
|---|---|---|
| Host bridge | `if_bridge` | `ng_bridge` node |
| Jail interface | `if_epair` pair (`epair0a`/`epair0b`) | `ng_eiface` (`ngethN`) |
| Gateway lives on | the bridge interface | a host-side `ng_eiface` |
| VLAN tagging | supported | not supported |

### Named networks

A named network is a persisted record (subnet, gateway, bridge, backend), not
a live interface. Creating one realizes it on the host; `blackship setup`
re-realizes it after a reboot, when bridges and eifaces are gone but the
record remains:

```sh
blackship network create default --subnet 10.0.1.0/24 --backend netgraph --bridge ngbridge0
```

```
Created network 'default' on bridge 'ngbridge0' (netgraph)
  Subnet: 10.0.1.0/24
  Gateway: 10.0.1.1
  Host gateway interface: ngeth0
```

Jails attach by name and inherit the backend, so nothing in the jail
definition needs to know which dataplane is in use:

```toml
[jails.network]
vnet = true
networks = ["default"]
ip = "10.0.1.10"
```

### How the netgraph backend is wired

`ng_bridge` is a kernel graph node with numbered `linkN` hooks. Blackship
hangs one `ng_eiface` off a hook per jail, plus one for the host itself,
which is where the gateway address lives:

```
                          ng_bridge (ngbridge0)
                          ├── link0 ── ng_eiface ngeth0   [host]  10.0.1.1
                          ├── link1 ── ng_eiface ngeth1   [jail web]  10.0.1.10
                          └── link2 ── ng_eiface ngeth2   [jail db]   10.0.1.11
host NIC (em0) ── PF NAT ── routing ── ngeth0
```

There is no epair pair and no `if_bridge`: the jail interface is moved into
the jail's vnet with `SIOCSIFVNET`, and traffic reaches the outside through
normal host routing plus a NAT rule. Outbound therefore needs
`net.inet.ip.forwarding=1` (Blackship sets it when it realizes a gateway) and
a NAT rule for the subnet in `pf.conf`:

```
nat on $ext_if inet from 10.0.1.0/24 to any -> ($ext_if)
```

Concurrent jail creation is safe: two creators racing for the same free
`linkN` retry the next index, and IP claims are arbitrated by the lease store
under a lock rather than by whoever wrote last.

### Interface ownership

Host-side interfaces are tagged into the `blackship` interface group
(`ifconfig -g blackship` lists them). Cleanup checks that tag before
destroying an interface it found by name, so a recycled name belonging to
something else is never torn down. Only the host end is tagged, because
moving an interface into a vnet strips its groups.

Jail interfaces also get a deterministic MAC by default: the FreeBSD OUI
`58:9c:fc` plus a hash of the jail name and bridge, so an address survives
restarts and differs between clones. Set `mac_address` to override.

### Gotcha: one namespace, two bridge types

Loading `ng_ether` gives every ethernet interface a netgraph node named after
itself, and that includes `if_bridge` interfaces. A named network created
with the epair backend on `blackship0` therefore occupies the name
`blackship0` in the netgraph namespace too, and a netgraph bridge cannot then
use it:

```
Error: Network error: NgNameNode(.:bridge_tmp, blackship0) failed: Address already in use
```

Give the two backends distinct bridge names (`blackship0` and `ngbridge0`).

### Port Forwardingemains the default and is what most setups want.

### Port Forwarding

Uses PF anchors to avoid modifying `/etc/pf.conf`:

```sh
# Expose nginx on port 80
blackship expose web -p 80

# Expose on specific host IP
blackship expose web -p 443 -I 192.168.1.100

# Different internal port
blackship expose web -p 8080 --internal 80
```

Add to `/etc/pf.conf`:
```
rdr-anchor "blackship"
anchor "blackship"
```

Port forwards are persisted under Blackship's data directory. After a PF
restart or host reboot, run `blackship setup` to recreate the anchor and
reapply the saved rules.

## Health Checks

All health checks are command-based (exit 0 = healthy).

### HTTP Check

```toml
[[jails.healthcheck.checks]]
name = "api"
command = "curl -sf http://localhost:8080/health"
target = "jail"
interval = 30
timeout = 10
```

### TCP Check

```toml
[[jails.healthcheck.checks]]
name = "postgres"
command = "nc -z localhost 5432"
target = "jail"
```

### Command Check

```toml
[[jails.healthcheck.checks]]
name = "nginx-running"
command = "service nginx status"
target = "jail"
```

### Monitoring

```sh
# One-time check
blackship health web

# Watch mode (updates every 5 seconds)
blackship health --watch --interval 5

# JSON output for scripting
blackship health --json
```

## Dependencies

Jails start in dependency order and stop in reverse:

```toml
[[jails]]
name = "app"
depends_on = ["cache", "database"]

[[jails]]
name = "cache"

[[jails]]
name = "database"
```

```sh
# Starts: database → cache → app
blackship up app

# Stops: app → cache → database
blackship down app
```

## Examples

### Web Application Stack

```toml
[config]
# data_dir defaults to ~/.local/share/blackship
zfs_enabled = true
zpool = "zroot"
dataset = "blackship"

[[jails]]
name = "postgres"
release = "15.1-RELEASE"
hostname = "db.local"
[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.10"
gateway = "10.0.1.1"

[[jails]]
name = "redis"
release = "15.1-RELEASE"
hostname = "cache.local"
[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.11"
gateway = "10.0.1.1"

[[jails]]
name = "webapp"
release = "15.1-RELEASE"
hostname = "app.local"
depends_on = ["postgres", "redis"]
[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.20"
gateway = "10.0.1.1"
[jails.network.dns]
nameservers = ["8.8.8.8"]
mode = "custom"

[jails.healthcheck]
enabled = true

[[jails.healthcheck.checks]]
name = "http"
command = "curl -sf http://localhost:3000/health"
target = "jail"
interval = 30
```

### Backup and Migration

```sh
# Create snapshot
blackship snapshot create webapp v1.0

# Export for migration
blackship export webapp -o webapp-v1.0.tar.zst

# On new host
blackship import webapp-v1.0.tar.zst --name webapp
# Edit blackship.toml to add jail config
blackship up webapp
```

## CI/CD Integration (Example)

This is an example of how Blackship could be used as a backend for CI/CD systems. This is not a built-in integration - it demonstrates how the `run`, `exec`, `cp`, and `rm` commands can be combined for CI/CD workflows.

### Example: Gitea Actions with act_runner

Blackship could be used as a backend for [Gitea Actions](https://docs.gitea.com/usage/actions/overview) via [act_runner](https://gitea.com/gitea/act_runner).

#### Setup

1. Bootstrap a release:
```sh
blackship bootstrap 15.1-RELEASE
```

2. Configure act_runner with jail labels:
```yaml
runner:
  labels:
    - "freebsd-15:jail://15.1-RELEASE"
```

3. Workflows targeting `runs-on: freebsd-15` would execute in ephemeral jails.

#### How it Would Work

When act_runner receives a job with a `jail://` label, the runner could:
1. Create an ephemeral jail via `blackship run --name gitea-runner-<id> --release <release> --detach`
2. Clone the repository into the jail using `blackship cp`
3. Execute each step via `blackship exec <jail> --workdir /workspace -- <command>`
4. Clean up via `blackship rm <jail> --force`

**Note:** This requires custom act_runner configuration or a wrapper script - it is not built into act_runner by default.

## Troubleshooting

### Jail won't start

```sh
# Check configuration
blackship check

# Try dry run
blackship up myjail --dry-run

# Clean up failed resources
blackship cleanup myjail --force
```

### Network issues

```sh
# List Blackship-managed networks
blackship network list

# Check jail IP
blackship exec myjail -- ifconfig

# Verify routing
blackship exec myjail -- netstat -rn
```

### ZFS issues

```sh
# Verify dataset exists
zfs list | grep blackship

# Check snapshots
blackship snapshot list myjail

# Manual cleanup
zfs destroy -r zroot/blackship/jails/myjail
```

### `blackship up` aborts where it used to warn

Resource-limit and VNET-attach failures are fatal: the jail is removed and
its resources are rolled back rather than left running in a half-configured
state. A jail with `[jails.resources]` set will now fail on a host without
RCTL instead of quietly ignoring its limits.

`kern.racct.enable` is a read-only tunable, so it cannot be set at runtime.
Add it to `/boot/loader.conf` and reboot:

```
kern.racct.enable="1"
```

### Rejected `params` entries

Manifest `params` cannot override the keys Blackship uses to establish jail
identity and isolation — `vnet`, `path`, `name`, `securelevel`,
`devfs_ruleset`, `enforce_statfs`, `allow.*` and similar. Those are reported
and ignored rather than applied. Set the supported options (`[jails.network]`,
`[jails.resources]`) instead.

### `ping` fails inside `blackship run`

Ephemeral `run` jails are not granted `allow.raw_sockets`, `allow.socket_af`
or `allow.chflags`. Use a managed jail defined in the manifest for workloads
that need raw sockets or `chflags`.

## License

BSD-3-Clause - See [LICENSE](LICENSE) file for details.

## Author

Abdelkader Boudih <oss@seuros.com>
