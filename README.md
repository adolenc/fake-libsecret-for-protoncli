# proton-drive without a keyring daemon

Running Proton's `proton-drive` CLI on a non-GNOME/KDE system fails with:

```
Failed to load session from secrets (ensure you have secrets available, read the
README for more information): The name org.freedesktop.secrets was not provided
by any .service files (code: 2)
```

This repo makes it work without installing a keyring daemon.

## Usage

Requires a C compiler and `make`. Nothing else.

```sh
./install.sh                          # uses proton-drive from $PATH
./install.sh /path/to/proton-drive    # or point at it explicitly
```

This builds the shim into `~/.local/lib/fakesecret/`, moves your binary to
`proton-drive.bin`, and installs a wrapper in its place. Then:

```sh
proton-drive auth login
```

opens the browser and writes the session in `~/.local/share/fake-secrets`.

## How it works

`proton-drive` is a [Bun](https://bun.sh)-compiled binary and uses Bun's
`Bun.secrets` API to store your session. On Linux that `dlopen()`s
`libsecret-1.so.0` and calls exactly five functions:

```
secret_password_lookup_sync
secret_password_store_sync
secret_password_clear_sync
secret_password_free
secret_service_search_sync
```

libsecret is only a *client*. It forwards those calls over D-Bus to whatever
owns the name `org.freedesktop.secrets` — gnome-keyring, KeePassXC,
KWallet, `pass-secret-service`. If nothing on your box provides that name,
libsecret has nowhere to forward to, and no amount of installing libsecret
helps.

`proton-drive` offers no way around this: no environment variable, no config
file fallback, no keyring backend option. (And there is no password to supply
in plaintext — `auth login` is browser-based OAuth; the stored secret is a
session token.)

`fakesecret.c` is a ~300-line stand-in for `libsecret-1.so.0` implementing
those five functions against a plaintext file. No daemon, no D-Bus, nothing
to install. A wrapper script puts it ahead of the real libsecret on the
loader path, so **only** `proton-drive` sees it — everything else on your
system that uses libsecret is unaffected.

## Security

**Your Proton session token is stored unencrypted** in
`~/.local/share/fake-secrets` (mode 0600). Anything running as your user can
read it. That is the entire point of this repo — it trades secrecy for not
having to run a keyring daemon.

Treat that file like a password. If that trade-off isn't acceptable, install
`gnome-keyring`, `keepassxc`, or `pass-secret-service` instead.

### Doing it by hand

If you'd rather not have a script rename your binary:

```sh
make
mkdir -p ~/.local/lib/fakesecret
cp libsecret-1.so.0 ~/.local/lib/fakesecret/
LD_LIBRARY_PATH=~/.local/lib/fakesecret proton-drive auth login
```

Prefix every `proton-drive` invocation the same way, or wrap it in a shell
alias.

## Uninstall

```sh
./install.sh --uninstall
rm ~/.local/share/fake-secrets    # optional: drops your stored session
```

## Troubleshooting

If a `proton-drive` update bumps its bundled Bun to a version that calls
libsecret differently, login may break. Run with tracing to see what it asks
for:

```sh
FAKESECRET_DEBUG=1 proton-drive fs list /
```

```
[fakesecret] key: com.oven-sh.bun.Secret|account=auth-session;service=ch.proton.drive/drive-sdk-cli;
[fakesecret] lookup -> miss
```

Environment variables:

| Variable | Meaning |
| --- | --- |
| `FAKESECRET_STORE` | Store file (default `~/.local/share/fake-secrets`) |
| `FAKESECRET_DEBUG` | Set to `1` to trace every call on stderr |

## Notes

Tested against the `proton-drive` CLI on Debian, x86-64. The shim sorts
attributes before building its lookup key, so it doesn't care what order the
caller passes them in. `secret_service_search_sync` returns an empty list —
it's only used for enumerating stored items, which the CLI doesn't rely on.

Unaffiliated with Proton.
