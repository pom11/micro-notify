# Delegated (as-a-person) setup

This is the operator guide for `[mail] mode = "delegated"` (design amendment
2026-10-30, A.1–A.4). App-only mode remains the default and the production
recommendation; nothing here changes it.

- `mnotify login` runs the device-code flow and stores the delegated token cache
  as the secret-store account `graph.delegated_token_cache`.
- `mnotify logout` deletes that local item. It is a local revoke only; the hard
  revoke is Entra ID → Users → *user* → **Revoke sessions** (and removing the
  delegated consent).
- `mnotify whoami` prints the signed-in UPN and access-token expiry, never a
  token.

The cache is a secret: on macOS it is one keychain item; on Linux and in
containers it is a file protected by the file secret backend
([ADMIN-SETUP.md](ADMIN-SETUP.md#linux--containers-file-secret-backend)). It
holds a refresh token, so treat a copy of it like the person's password.

## Running delegated mode in a Linux container

"Headless" here means exactly one thing: the **container** needs no browser, X
server or TTY beyond stdout. The device-code flow prints a verification URL and
a user code to stdout; a human opens that URL in a browser on **any** machine and
types the code. `docker run --rm -it ... mnotify login --json` started from the
host terminal works. `nohup`, cron or CI with nobody to visit the URL does
**not** work — there is no way around the one human interaction per login. The
poll continues until the human acts or msal's flow expires; the existing expiry
error text is unchanged.

The container needs the same file-backend variables as app mode, plus a config
file and a **writable** secrets directory:

```sh
# One-time: a writable volume for the token cache (and any other secrets).
docker volume create mnotify-delegated-secrets

docker run --rm -it \
  -e MICRO_NOTIFY_CONFIG=/config/config.toml \
  -e MICRO_NOTIFY_SECRETS=file \
  -e MICRO_NOTIFY_SECRETS_DIR=/var/lib/mnotify/secrets \
  -v "$PWD/delegated.toml:/config/config.toml:ro" \
  -v mnotify-delegated-secrets:/var/lib/mnotify/secrets \
  micro-notify:latest \
  mnotify login --json
```

Use the image and config path you already deploy. A minimal `delegated.toml`
uses the documented placeholders:

```toml
[mail]
mode = "delegated"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
sender = "me@contoso.com"
auth = "certificate"

[allow]
domains = ["example.com"]
addresses = ["person@contoso.com"]
```

`[mail] sender` must be the UPN that actually signs in; delegated mode refuses a
send as anyone else (`mnotify doctor` checks this before `--send-test`).

### The secrets directory must be writable at runtime

This is the important difference from app mode. App mode only reads its
certificate/secret files, so a read-only Docker secret mount is enough.
Delegated mode **writes the cache back** whenever msal refreshes a token — which
`mnotify mail send` may do at any time, not only during login. The secrets
directory (at minimum the cache file's parent directory, because writes are an
atomic temp file + rename in that directory) must therefore be writable by the
container uid for the lifetime of the deployment.

If `MICRO_NOTIFY_SECRETS=file` and that path is read-only, `mnotify login` fails
closed with exit 4 before starting the device flow, naming the cache path and
saying it needs a **WRITABLE** secrets dir. A pre-provisioned cache file does not
remove that requirement: refresh still needs to write the updated cache back.

### Honest limits

- **There is no OS keychain on Linux.** The cache is a plaintext `0600` file
  readable by any process running as the container uid, and by root on the host.
  A stolen cache file is a stealable refresh token until consent/session expiry.
  Mitigate with short token lifetimes, `mnotify logout` when done, and revoking
  the app/sessions in Entra.
- **Every login needs one human with a browser.** Device-code auth is an
  interactive grant; a container alone cannot complete it.
- **The refresh token dies with the user's consent or session lifetime.** At that
  point a human must run `mnotify login` again. Delegated mode is therefore the
  wrong shape for a 24/7 alert sender that must run unattended for months: app
  mode is the production default, and this card does not change that advice.
  Delegated mode is for sending as a real person while that person's consent is
  alive.

### Two configs on one machine

`MICRO_NOTIFY_CONFIG` points at an alternate config file; it carries a path,
never a secret value. This is how an app-mode deployment and a delegated setup
coexist on one host (the pattern proven in the D6 live acceptance):

```sh
MICRO_NOTIFY_CONFIG=/etc/mnotify/delegated.toml mnotify login
MICRO_NOTIFY_CONFIG=/etc/mnotify/delegated.toml mnotify whoami
MICRO_NOTIFY_CONFIG=/etc/mnotify/delegated.toml mnotify mail send ...
```

Keep each config's `MICRO_NOTIFY_SECRETS_DIR` separate if the two setups use
different identities, so `mnotify logout` for one cannot remove the other's
cache. As with app mode, `mnotify logout` is local to the store it is pointed
at; the tenant-wide revoke still happens in Entra.
