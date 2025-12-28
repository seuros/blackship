# Blackship

A FreeBSD jail orchestrator with TOML configuration, dependency management, state machine lifecycle control, and ZFS integration.

## Features

- **Declarative Configuration**: Define jails in TOML with dependencies, networking, and hooks
- **Dependency Management**: Automatically start/stop jails in correct order using dependency graph
- **State Machine Lifecycle**: Clean state transitions (stopped → starting → running → stopping)
- **VNET Networking**: Bridge-based networking with epair interfaces, static IPs, and MAC addresses
- **ZFS Integration**: Automatic dataset creation, snapshots, clones, and efficient export/import
- **Jailfile Templates**: Docker-like build system for reproducible jail creation
- **Health Checks**: HTTP, TCP, and command-based health monitoring
- **Lifecycle Hooks**: Run scripts at start/stop with configurable failure handling
- **Port Forwarding**: PF-based port exposure with source IP binding
- **Shell Completion**: Bash, Zsh, and Fish completions

## Requirements

- FreeBSD 14.0+ with jail support
- ZFS (optional, for snapshots/clones)
- PF (optional, for port forwarding)

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

## Quick Start

### 1. Initialize Configuration

Create `blackship.toml`:

```toml
[config]
data_dir = "/var/blackship"
releases_dir = "/var/blackship/releases"
cache_dir = "/var/blackship/cache"
zfs_enabled = true
zpool = "zroot"
dataset = "blackship"

[[jails]]
name = "web"
release = "15.0-RELEASE"
hostname = "web.local"

[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.10"
gateway = "10.0.1.1"
```

### 2. Bootstrap a Release

```sh
# Download and extract FreeBSD base
blackship bootstrap 15.0-RELEASE

# List available releases
blackship releases
```

### 3. Create Network

```sh
# Create bridge with gateway
blackship network create default --subnet 10.0.1.0/24 --gateway 10.0.1.1 --bridge blackship0
```

### 4. Start Jails

```sh
# Start a specific jail
blackship up web

# Start all jails
blackship up --all

# Dry run (show what would happen)
blackship up --all --dry-run
```

### 5. Interact with Jails

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
data_dir = "/var/blackship"           # Base data directory
releases_dir = "/var/blackship/releases"  # FreeBSD releases
cache_dir = "/var/blackship/cache"    # Download cache
mirror_url = "https://download.freebsd.org"  # FreeBSD mirror
zfs_enabled = true                    # Enable ZFS features
zpool = "zroot"                       # ZFS pool name
dataset = "blackship"                 # Base dataset name
```

### Jail Definition

```toml
[[jails]]
name = "myapp"                        # Jail name (required)
release = "15.0-RELEASE"              # Base release
path = "/jails/myapp"                 # Custom path (optional)
hostname = "myapp.local"              # Hostname
depends_on = ["database"]             # Dependencies

[jails.network]
vnet = true                           # Enable VNET
bridge = "blackship0"                 # Bridge interface
ip = "10.0.1.10"                      # Static IP
gateway = "10.0.1.1"                  # Default gateway
mac_address = "02:00:00:00:00:01"     # Static MAC (optional)

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
phase = "post_start"
target = "jail"
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
| `blackship up [jail] [--all] [--dry-run]` | Start jail(s) with dependencies |
| `blackship down [jail] [--all] [--dry-run]` | Stop jail(s) in reverse order |
| `blackship restart [jail] [--all] [--dry-run]` | Restart jail(s) |
| `blackship ps [--json]` | List jail status |
| `blackship check` | Validate configuration |
| `blackship init` | Initialize ZFS datasets |
| `blackship cleanup <jail> [--force]` | Clean up failed jail resources |

### Console & Execution

| Command | Description |
|---------|-------------|
| `blackship console <jail> [-u user]` | Open interactive shell |
| `blackship exec <jail> [-u user] -- <cmd>` | Execute command in jail |

### Bootstrap & Releases

| Command | Description |
|---------|-------------|
| `blackship bootstrap <release> [-f] [-a archives]` | Download FreeBSD release |
| `blackship releases [list\|delete\|verify] [--json]` | Manage releases |

### Networking

| Command | Description |
|---------|-------------|
| `blackship network create <name> -s <subnet> [-g gw] [-b bridge]` | Create network |
| `blackship network destroy <name> [--force]` | Destroy network |
| `blackship network list` | List networks |
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

### Export & Import

| Command | Description |
|---------|-------------|
| `blackship export <jail> [-o file] [--zfs-send]` | Export to archive |
| `blackship import <file> [-n name] [--force]` | Import from archive |

### Build System

| Command | Description |
|---------|-------------|
| `blackship build [-f Jailfile] [-n name] [--build-arg K=V] [--dry-run]` | Build from Jailfile |
| `blackship template list` | List templates |
| `blackship template inspect <file>` | Show Jailfile details |
| `blackship template validate <file>` | Validate Jailfile |

### Health & Monitoring

| Command | Description |
|---------|-------------|
| `blackship health [jail] [-w] [-i interval] [--json]` | Health check status |
| `blackship supervise` | Start Warden supervisor for auto-restart |
| `blackship logs <jail> [-f] [-n lines]` | Tail jail logs |

### Shell Completion

| Command | Description |
|---------|-------------|
| `blackship completion bash\|zsh\|fish` | Generate shell completion |

## Jailfile Format

Jailfiles define reproducible jail builds, similar to Dockerfiles:

```dockerfile
# Jailfile
FROM 15.0-RELEASE

# Metadata
METADATA name=nginx-jail version=1.0

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

from = "15.0-RELEASE"

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

When `zfs_enabled = true`, Blackship:

1. Creates datasets automatically: `zpool/blackship/jails/<name>`
2. Enables snapshots and clones
3. Supports ZFS send/receive for fast export/import

### Snapshot Workflow

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
```

## Networking

### VNET Setup

Blackship uses VNET jails with epair interfaces connected to a bridge:

```
Host Bridge (blackship0)
├── epair0a ←→ epair0b (jail: web, 10.0.1.10)
├── epair1a ←→ epair1b (jail: db, 10.0.1.11)
└── gateway: 10.0.1.1
```

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
data_dir = "/var/blackship"
zfs_enabled = true
zpool = "zroot"
dataset = "blackship"

[[jails]]
name = "postgres"
release = "15.0-RELEASE"
hostname = "db.local"
[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.10"
gateway = "10.0.1.1"

[[jails]]
name = "redis"
release = "15.0-RELEASE"
hostname = "cache.local"
[jails.network]
vnet = true
bridge = "blackship0"
ip = "10.0.1.11"
gateway = "10.0.1.1"

[[jails]]
name = "webapp"
release = "15.0-RELEASE"
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
# List bridges
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

## License

MIT - See [LICENSE](LICENSE) file for details.

## Author

Abdelkader Boudih <oss@seuros.com>
