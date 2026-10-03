# Run dae as a Daemon Service

Run dae as a [systemd](https://wiki.debian.org/systemd) service to start it at boot.
This requires a distribution that uses systemd as its service manager.

## Prerequisites

### Optional Geo Data Files

For traffic splitting, dae uses [geoip.dat](https://github.com/v2fly/geoip/releases/latest) and [geosite.dat](https://github.com/v2fly/domain-list-community/releases/latest).

```shell
mkdir -p /usr/local/share/dae/
pushd /usr/local/share/dae/
curl -L -o geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
curl -L -o geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
popd
```

dae looks for `geoip.dat` and `geosite.dat` in the directory of the config file, then in the platform data directories (`/usr/local/share/dae`, `/usr/share/dae`, `$XDG_DATA_HOME/dae`, ...). To add another directory, set the `DAE_LOCATION_ASSET` environment variable to the directory that holds the `.dat` files:

```bash
DAE_LOCATION_ASSET=/usr/share/v2ray dae run -c /etc/dae/config.dae
```

`DAE_LOCATION_ASSET` is read from the environment of the `dae` process itself. A value you export in an interactive shell does **not** reach a daemon launched by systemd, and `sudo` resets the environment unless you pass `-E`. For a systemd service, put it in a drop-in:

```bash
sudo systemctl edit dae.service
```

```ini
[Service]
Environment=DAE_LOCATION_ASSET=/usr/share/v2ray
```

The shipped unit also reads the optional `/etc/dae/dae.env`, which is not part of the package, so an upgrade cannot overwrite it:

```bash
printf 'DAE_LOCATION_ASSET=/usr/share/v2ray\n' | sudo tee /etc/dae/dae.env
sudo chmod 600 /etc/dae/dae.env
sudo systemctl restart dae
```

When starting `dae` manually, `sudo -E dae run ...` preserves the variable; a bare `sudo dae run ...` does not. Running `dae run ...` without `sudo` as a non-root user also works: dae escalates through `sudo -E` itself and keeps the variable. The error reported when the file is not found names `DAE_LOCATION_ASSET` and whether the process saw it, so the lookup failure is self-explanatory.

### Configuration File

Download the sample configuration to the recommended directory, `/etc/dae`:

```bash
mkdir -p /etc/dae
curl -L -o /etc/dae/config.dae https://github.com/daeuniverse/dae/raw/main/example.dae
chmod 600 /etc/dae/config.dae
```

## Download Precompiled Binaries

[Release binaries](https://github.com/daeuniverse/dae/releases) and
[nightly builds](https://github.com/daeuniverse/dae/actions/workflows/build-nightly.yml) are available.

Nightly builds let you try new features. Proposed changes are usually submitted
in PRs and built into cross-platform binaries by GitHub Actions. New features
may contain bugs, so use these builds at your own risk. Testing them helps
assess feature stability and identify bugs.

```bash
sudo chmod +x ./dae
sudo install -Dm755 dae /usr/bin/

# helper
dae [-h,--help]
# check version
dae version
```

## Setup

```bash
# download the sample systemd.service
sudo curl -L -o /etc/systemd/system/dae.service https://github.com/daeuniverse/dae/raw/main/install/dae.service

# reload and restart daemon to take effect
sudo systemctl daemon-reload
sudo systemctl enable dae --now
sudo systemctl status dae
```

## Memory and Transparent Huge Pages

`GOMEMLIMIT` defaults to 90% of the process's cgroup memory ceiling.
Only `memory.max` determines this ceiling. The bundled unit no longer sets
`MemoryHigh`, which the runtime cannot use as a bound.
An explicit `GOMEMLIMIT` environment variable always takes precedence.

When transparent huge pages are set to `always`, the kernel can increase
dae's resident set without growth in the live Go heap. On every start, reload
and rollback, dae calls `prctl(PR_SET_THP_DISABLE)` for its own process with
the current `disable_thp` value. `true` passes 1 and opts the process out.
The default, `false`, passes 0 and clears any per-process opt-out, including
one inherited from the parent process, so dae follows the system-wide THP
setting. Neither value changes `/sys/kernel/mm/transparent_hugepage`:

```shell
global {
  disable_thp: true
}
```

## Check System Logs

```bash
sudo journalctl -xefu dae
```
