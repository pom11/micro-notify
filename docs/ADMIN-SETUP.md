# Admin setup — one-time tenant steps

Audience: the tenant administrator. This is the operator-side half of
[`README.md`](../README.md): nothing in `mnotify` works until these steps are done
once per tenant. Every command here is run by a human with tenant-admin rights; the
agent or script that later calls `mnotify` never needs any of them.

Scope is fixed by the design contract:
[`docs/design/2026-10-27-micro-notify-design.md`](design/2026-10-27-micro-notify-design.md)
§6 (these steps), §3.1 (why the mailbox must be scoped), §2 (the anti-goal this doc
exists to prevent).

---

## Before you start

What you need:

- A Microsoft 365 tenant with Exchange Online, and an account that can register an
  application in Microsoft Entra ID and grant admin consent (Application
  Administrator + Privileged Role Administrator, or Global Administrator).
- For step 2, membership of the **Organization Management** role group in Exchange
  Online (that is the group holding the delegating assignment for the application
  roles), and the Exchange Online PowerShell module
  (`Connect-ExchangeOnline`).
- The macOS machine that will run `mnotify`, with the CLI installed
  (`mnotify --version` prints a version).
- A mailbox to send from. It may be a licensed user mailbox or a shared mailbox —
  see [step 5](#step-5--confirm-the-mailbox-license) for why that choice is free.

Placeholders used throughout. Replace every angle-bracket value with your own;
none of them is a real value.

| Placeholder                     | What it is                                                                 |
| ------------------------------- | -------------------------------------------------------------------------- |
| `<tenantId>`                    | Entra directory (tenant) ID, a GUID                                         |
| `<clientId>`                    | the app registration's **Application (client) ID**, a GUID                  |
| `<enterpriseAppObjectId>`       | the same app's **Object ID** on the Enterprise applications page, a GUID    |
| `noreply@example.com`           | the one mailbox this app may send from                                      |
| `ops@example.com`               | a second mailbox in the same tenant, used only for the negative test        |
| `alerts` / `dm`                 | Teams target names you choose (`[A-Za-z0-9_-]`, no spaces)                  |

The all-zeroes GUID `00000000-0000-0000-0000-000000000000` appears in sample output
below as the documented stand-in for a real GUID. It is a placeholder, like the rest.

Two rules that hold for the whole procedure:

- **A secret is only ever typed at a hidden prompt.** The certificate private key,
  the client secret and every Teams webhook URL go to the macOS keychain through
  `mnotify setup` / `mnotify teams targets add`. There is no flag, environment
  variable or config key that takes a secret, and that is deliberate: a secret on a
  command line lands in shell history and in `ps` output.
- **The Entra grant and the Exchange grant are separate and additive.** Step 3 is
  not a cleanup nicety; it is the step that makes step 2 mean anything.

---

## Step 1 — Register the app in Entra and give it the certificate

Design §6 step 1. The certificate is generated on the machine that will run
`mnotify`, so the private key never leaves it.

### 1.1 Create the app registration (you need its IDs before the next sub-step)

1. Entra admin center → **App registrations** → **New application registration**.
2. Name: `micro-notify`. Supported account types: **Accounts in this organizational
   directory only** (single tenant). No redirect URI, no platform configuration.
3. On the overview page note the **Directory (tenant) ID** (`<tenantId>`) and the
   **Application (client) ID** (`<clientId>`).

Do not add a secret and do not add permissions yet.

### 1.2 Generate the certificate on the machine that runs `mnotify`

`mnotify setup` needs the two IDs from 1.1, which is why the app registration comes
first. Run it at a terminal:

```sh
mnotify setup --gen-cert \
  --tenant-id <tenantId> \
  --client-id <clientId> \
  --sender noreply@example.com \
  --auth certificate \
  --allow-domain example.com
```

It writes `~/.config/mnotify/config.toml` (mode 0600, no secrets in it), stores the
private key and the certificate thumbprint in the keychain under service `mnotify`,
prints the SHA-1 fingerprint, and prints the path of the **public** certificate it
wrote for you to upload (by default
`~/.config/mnotify/entra-certificate.pem`). Copy that printed path — the next
sub-step uploads exactly that file.

Non-interactive agents can use the same flags plus `--json`; there is
deliberately no `--client-secret` flag (see 1.5 for the secret fallback).
`--allow-domain example.com` is what makes sends possible at all — with an empty
allowlist every send is refused (design §3.3); you can widen it later with
`mnotify setup --force`.

### 1.3 Upload the public certificate

Back in Entra: your app registration → **Certificates & secrets** →
**Certificates** → **Upload certificate** → choose the file printed in 1.2. Entra
shows the same thumbprint the setup command printed; confirm they match.

The generated certificate is valid for 825 days, which is Entra's maximum for a
one-time upload. When it expires, re-run 1.2 and re-upload (see
[Rotating the certificate](#rotating-the-certificate)).

### 1.4 Add the Graph application permission and consent

1. **API permissions** → **Add a permission** → **Microsoft Graph** →
   **Application permissions**.
2. Search `Mail.Send`, add **Mail.Send** ("Send mail as any user").
3. **Grant admin consent for \<your tenant\>** → Yes. This is the tenant-wide grant
   that step 3 removes again — it is here because the permission must be *declared*
   before the consent can exist, and the Exchange role in step 2 is what bounds it.
4. **Authentication** → no platform, no redirect URI, nothing to add. If your tenant
   shows a "Allow public client flows" toggle, leave it **No**.

### 1.5 Optional: client-secret authentication instead

Certificate is the default and what the rest of this document assumes. If the tenant
policy requires a client secret: skip 1.2's `--gen-cert` and run

```sh
mnotify setup --auth secret --tenant-id <tenantId> --client-id <clientId> \
  --sender noreply@example.com --allow-domain example.com
```

`mnotify` then asks for the secret with hidden input and stores it in the keychain.
Type it only at that prompt; never into a flag, an environment variable or a file.
In Entra you would create that secret under **Certificates & secrets** →
**Client secrets**. Steps 2 and 3 are identical either way — the scoping is attached
to the service principal, not to the credential kind.

### 1.6 Checkpoint

```sh
mnotify doctor
```

Expected at this point: `config` pass, `keychain` pass, `teams` pass (no targets
yet is fine), and the token/`Mail.Send` checks pass once the consent from 1.4 has
propagated. A failure names the check and prints a `fix:` hint.

This checkpoint is where you prove the Entra grant is live: `doctor` reads the
`Mail.Send` role out of the token Entra issued, and while the consent from 1.4 still
stands the line reads `token: pass`. Step 3 deliberately removes that grant, so
**after** step 3 the `token` line turns yellow `warn` ("not verifiable from the
token"), the run continues, and `mnotify doctor` still exits 0 — see
[3.2](#32-remove-the-consent) for the captured output. `doctor` is the verification
tool both before and after step 3; `mnotify mail send` stays the positive post-step-3
test that a real message goes out.

---

## Step 2 — Scope the app to the one mailbox in Exchange Online

Design §6 step 2. This is the control that satisfies the design §2 anti-goal "the
app registration can send as ANY mailbox in the tenant". Entra's `Mail.Send`
application permission is tenant-wide by construction; Exchange Online **RBAC for
Applications** is what narrows it to `noreply@example.com`.

Run all of this in an Exchange Online PowerShell session as a member of
**Organization Management**:

```powershell
Connect-ExchangeOnline
```

### 2.1 Point Exchange at the Entra service principal

```powershell
New-ServicePrincipal -AppId <clientId> -ObjectId <enterpriseAppObjectId> -DisplayName micro-notify
```

Both IDs come from Entra. `-ObjectId` is the **Enterprise application** Object ID —
not the value on the App registrations page. If the cmdlet insists on `-ServiceId`,
pass the same `<enterpriseAppObjectId>` value for it.

### 2.2 Create a scope that matches exactly the sender mailbox

```powershell
New-ManagementScope -Name mnotify-noreply `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'noreply@example.com'"
```

One mailbox, matched on its primary address. If you would rather be able to add
senders later without touching the role assignment, filter on a mail-enabled
security group membership instead (`MemberOfGroup -eq '<groupDn>'`) and keep the
group down to the mailboxes you actually mean.

### 2.3 Assign the application role inside that scope

```powershell
New-ManagementRoleAssignment -App <clientId> -Role "Application Mail.Send" `
  -CustomResourceScope mnotify-noreply
```

`-App` takes the client ID here. If the assignment is rejected, or the negative test
in 3.3 comes back with `Blocked by tenant configured AppOnly AccessPolicy settings`,
retry `-App` with `<enterpriseAppObjectId>` instead — the two IDs are easy to swap
and the error message does not say which one it got.

Note on scope type: use `-CustomResourceScope`. An **exclusive** management scope
does not restrict application access, so an exclusive scope here silently does
nothing.

### 2.4 Prove the scope with the test cmdlet

Positive case — the mailbox inside the scope must come back `InScope True`:

```powershell
Test-ServicePrincipalAuthorization -Identity <clientId> `
  -Resource noreply@example.com | Format-Table
```

```text
RoleName               GrantedPermissions  AllowedResourceScope  ScopeType             InScope
--------               ------------------  --------------------  ---------             -------
Application Mail.Send  Mail.Send           mnotify-noreply       CustomRecipientScope  True
```

Negative case — a second mailbox in the same tenant must come back `InScope False`:

```powershell
Test-ServicePrincipalAuthorization -Identity <clientId> `
  -Resource ops@example.com | Format-Table
```

```text
RoleName               GrantedPermissions  AllowedResourceScope  ScopeType             InScope
--------               ------------------  --------------------  ---------             -------
Application Mail.Send  Mail.Send           mnotify-noreply       CustomRecipientScope  False
```

`InScope False` means "the app holds this role, but not over this mailbox" — exactly
the state we want. A row whose `InScope` is `Not Run` means `-Resource` was omitted.
A row with scope `Organization` instead of `mnotify-noreply` means the assignment in
2.3 did not take, so fix that before continuing.

Keep this session open for step 3.

---

## Step 3 — Remove the tenant-wide Entra consent, then re-test

Design §6 step 3. Do not skip this and do not defer it.

### 3.1 Why this step exists

Microsoft Entra permissions and Exchange Online application RBAC are **separate
authorization systems, and they are additive**. Entra's `Mail.Send` application
permission, once consented tenant-wide, authorises the app to send as any mailbox in
the directory — including every user mailbox, the admin mailboxes, and any mailbox
added next month. The scoped `Application Mail.Send` role from step 2 does **not**
narrow that grant; the union of the two is what Graph enforces, and the union is
tenant-wide.

So while the Entra consent stands, step 2 is decoration: `Test-ServicePrincipal-
Authorization` will faithfully report `InScope False` for `ops@example.com` and the
app will still be able to send as it. The scoped Exchange role is the only thing
that constrains the app, and it only has force once it is the only grant left. The
design states the anti-goal in §2: a build where the app can send as any mailbox
**failed**, however green its tests are.

### 3.2 Remove the consent

In Entra → the app registration → **API permissions**: select **Mail.Send** →
**Remove** (or, on the Enterprise application's **Permissions** page, **Grant
admin consent** → remove consent for `Mail.Send`). Removing the *consent* is what
matters; deleting the permission line as well also stops anyone re-consenting it by
accident later, and nothing in `mnotify` needs it once the Exchange role exists.

`mnotify doctor` reads the `roles` claim out of the token it acquires. That claim is
what Entra fills from the tenant-wide consent you are about to delete, so once the
consent is gone the claim is simply not in the token any more — and `doctor` reports
that as a yellow `warn`, not as a failure. This is the captured output on a tenant
*after* step 3 (it also prints with `--json`: `ok: true`, `exitCode: 0`,
`checks[]` identical, `token.status == "warn"`; the warn line goes to stdout, only a
`fail` goes to stderr):

```text
$ mnotify doctor          # tenant AFTER design §6 step 3
config: pass — /Users/…/config.toml
keychain: pass — present: graph.certificate_pem, graph.certificate_thumbprint
teams: pass — no targets configured
token: warn — token acquired; Mail.Send not verifiable from the token — its roles claim is absent or empty. Expected after design §6 step 3: the Exchange Online scoped Application Mail.Send role is invisible to the Entra roles claim. Prove the grant with `mnotify doctor --send-test <addr>`; do not re-grant the tenant-wide consent to silence this line
allow: pass — 1 domain(s), 0 address(es)
send-test: skipped
$ echo exit=$?
exit=0
```

Green with one warn is the expected end state of a correctly scoped app: the run
continues past the `token` line (`config`, `keychain`, `teams` and `allow` all still
report), and `--send-test` is reachable. **Do not "fix" the warn line by re-granting
the consent.** The warn says only that this one thing cannot be read from the token —
the grant that matters now lives in Exchange Online application RBAC, which the Entra
`roles` claim cannot see. Re-consenting `Mail.Send` tenant-wide would silence the
line and undo step 3, which is the opposite of what you came here to do.

The positive test after step 3 is a real send: `mnotify doctor --send-test
noreply@example.com` (the same single guarded send 3.3 performs) or a plain
`mnotify mail send`. Before you remove the consent, this same checkpoint is where the
Entra grant gets proven: run `mnotify doctor --send-test noreply@example.com` while
the consent is still in place and it should pass end to end, `token: pass` and all.

What `token: fail` (exit 4) means *after* step 3 — a real fault, not the steady state:
an `AADSTS…` detail is a credential problem (1.2/1.3), "roles claim could not be read"
is a token shape Entra does not produce, and a `roles` list that names other roles but
not `Mail.Send` means someone re-granted the tenant-wide consent — undo it.

Propagate, then test: changes to application permissions and application RBAC are
cached, and that cache is 30 minutes to 2 hours depending on how recently the app
made calls (`Test-ServicePrincipalAuthorization` bypasses the cache; real API calls
do not). If a test in 3.3 or 3.4 contradicts the `Test-ServicePrincipalAuthorization`
output, wait 30 minutes and run it again before you believe the discrepancy.

### 3.3 Positive re-test: the scoped mailbox still sends

With the consent gone, send one real message to the scoped mailbox itself — this is
the positive test that no longer relies on the Entra role:

```sh
mnotify mail send --to noreply@example.com \
  --subject "mnotify scoped send test" --body "sent with the Exchange-scoped role only" \
  --json
echo "exit=$?"
```

Expect `exit=0` and a `sent` document carrying the Graph request-id. The equivalent
one-command version is `mnotify doctor --send-test noreply@example.com` — the same
single guarded send, and the re-test design §6 step 3 asks for: it is reachable after
step 3 again, because the `warn` on the `token` line does not stop the run. Then
confirm from the audit log:

```sh
mnotify log --tail 3
```

Look for the `sent  mail` line for that attempt (recipients and subject, never a
body).

### 3.4 Negative test: a sender outside the scope must be refused

There is no sender flag on `mnotify mail send` — the sender comes from the config
file, which is what makes this test the right shape. `[mail] sender` is not a
secret, so editing it is safe; put the original value back afterwards.

```sh
# 1. in ~/.config/mnotify/config.toml, temporarily set the sender to a mailbox
#    OUTSIDE the scoped role:
#      [mail]
#      sender = "ops@example.com"

# 2. send to an address that IS on the allowlist, so the guard lets it through:
mnotify mail send --to noreply@example.com \
  --subject "mnotify scoped-mailbox negative test" \
  --body "expecting a refusal" --json
echo "exit=$?"
```

Expected: the refusal, and exit code **5**.

```text
{"exitCode": 5, "message": "Graph sendMail failed (HTTP 403, code ..., Graph request-id ...)", "ok": false, "outcome": "error"}
exit=5
```

`403` is the answer that matters — it is Exchange Online refusing the app's request
to send as a mailbox outside the scope. `mnotify` maps any non-2xx from Graph onto
exit 5 (design §4), and the Graph request-id in the message is what support needs if
it is instead a `401` (credential problem) or a `403` whose text says
`Blocked by tenant configured AppOnly AccessPolicy settings` (see the `-App` note in
2.3). If the send **succeeds**, the Entra consent is still in effect or the cache has
not expired — go back to 3.2.

Restore the sender afterwards, either by editing the file back or:

```sh
mnotify setup --force --sender noreply@example.com \
  --tenant-id <tenantId> --client-id <clientId> --auth certificate \
  --allow-domain example.com
```

`--force` rewrites the config and preserves your `[teams.targets]` entries.

---

## Step 4 — Teams Workflows targets

Design §3.2 and §6 step 4. Teams Workflows needs no app registration, no Graph
permission and no bot registration; each workflow hands out an HTTPS webhook URL
whose query string carries a signature. **That URL is a secret.** Anyone who has it
can post into the channel or as the Workflows bot, so it goes to the keychain and
never to the config file, a flag, or a terminal log line.

The webhook URLs you copy out of Teams are on `*.environment.api.powerplatform.com`
hosts (older tenants: `*.logic.azure.com`). Do not paste them anywhere except the
prompt below.

### 4.1 One workflow per channel

For each channel that should receive messages:

1. In Teams, hover the channel name → **···** → **Workflows**.
2. Search the templates for **Post to a channel when a webhook request is received**
   and pick it (some tenants show it as "Send webhook alerts to a channel" — that
   plainer template renders only a `text` field and will not render the card
   `mnotify` builds, so prefer the webhook-request template; if only the plain one
   exists, build the flow in Power Automate instead, as below).
3. Choose the team and channel, confirm the connection, **Add workflow**.
4. Copy the **Workflow URL** it shows.

In Power Automate (`make.powerautomate.com`) the equivalent flow is: *Instant cloud
flow* → trigger **When a Teams webhook request is received** → action **Post card in
a chat or channel** with *Post as* **Flow bot**, *Post in* **Channel**, your team and
channel, and the Adaptive Card field bound to
`first(triggerBody()?['attachments'])?['content']`. Save, then read the trigger's
**HTTP URL**.

One URL is bound to one channel: for three channels, three workflows.

### 4.2 The single DM workflow (one per tenant, not one per person)

A person cannot be addressed by a per-recipient workflow URL, so there is exactly
one DM workflow and the recipient is supplied per request:

1. In Power Automate, create an *Instant cloud flow* with trigger **When a Teams
   webhook request is received**.
2. Add action **Post card in a chat or channel**:
   - **Post as**: `Flow bot`
   - **Post in**: `Chat with Flow bot`
   - **Recipient**: `triggerBody()?['recipient']` (enter it via the expression `fx`
     editor, as a raw expression, not as a string inside quotes)
   - **Adaptive Card**: `first(triggerBody()?['attachments'])?['content']`
3. Save, and copy the trigger's **HTTP URL**.

`mnotify` posts `{"recipient": "<upn>", "attachments": [<card>]}` to this URL, which
is what those two expressions read (design §3.2). People get the message from the
Workflows bot in a chat; they can reply to that chat, but `mnotify` does not read
replies in v1.

### 4.3 Store each URL with `mnotify`

One command per workflow — it prompts for the URL with hidden input, writes it to
the keychain, and records only the name and kind in the config:

```sh
mnotify teams targets add alerts --kind channel
mnotify teams targets add dm --kind dm
```

Each prompt reads `Workflows webhook URL for teams target '<name>' (input hidden,
stored in the keychain):`. Paste at the prompt only. The keychain account is
`teams:<name>` under service `mnotify`.

Check what is configured — presence only, never a URL:

```sh
mnotify teams targets list
```

```text
alerts                   channel  present
dm                       dm       present
```

Remove one (config entry *and* keychain item) with
`mnotify teams targets remove alerts`. If a URL is ever exposed, remove the target,
delete or recreate the workflow in Teams, and add the new URL.

### 4.4 Check it, then use it

```sh
# payload inspection, no network call:
mnotify teams send alerts --title "Build 42" --text "nightly run finished" --dry-run

# real posts (each consumes one unit of the daily cap):
mnotify teams send alerts --title "Build 42" --text "nightly run finished"
mnotify teams send dm --to someone@example.com --text "the deploy needs your approval"
```

A `dm` target requires `--to <UPN>`, and that UPN must satisfy the allowlist like
any other recipient; a `channel` target rejects `--to`.

---

## Step 5 — Confirm the mailbox license

Design §6 step 5. Graph `sendMail` works for both kinds, so pick whichever fits your
tenant:

- **Shared mailbox** — no licence needed, no sign-in, and nothing expires. This is
  the usual choice for a notification address. Make sure `PrimarySmtpAddress` is the
  address you used in 2.2, and that nobody has an auto-reply or mailbox-forwarding
  rule on it that would make the tenant-wide blast radius worse than intended.
- **Licensed user mailbox** — fine too, but it is a real user account: keep it
  cloud-only, block interactive sign-in if your tenant allows it, and remember the
  app can send as it, so it should hold nothing you would not want quoted back.

Either way `mnotify` never reads the mailbox (design §2 non-goal), so no
"FullAccess" or send-as delegation to a human is required for the tool to work.

Set a `Reply-To` so replies reach a person rather than an unread mailbox:

```sh
mnotify setup --force --sender noreply@example.com --reply-to ops@example.com \
  --tenant-id <tenantId> --client-id <clientId> --auth certificate \
  --allow-domain example.com
```

---

## Final verification

Run these in order. This block runs *after* step 3 removed the Entra consent, so
`mnotify doctor` is expected **green with one `warn`** — the `token` line reporting
"not verifiable from the token". That is the correct end state; see 3.2, and never
re-grant the consent just to silence it. A `token: fail` here is a real problem: an
`AADSTS…` detail means the credential, "could not be read" means an unexpected token
shape, and a `roles` list naming other roles but not `Mail.Send` means someone
re-granted the tenant-wide consent — undo it.

```sh
# 1. config, keychain and teams pass; token reports warn "not verifiable" (by design):
mnotify doctor

# 2. exactly what would be sent, no network call:
mnotify mail send --to noreply@example.com --subject "dry run" --body "x" --dry-run

# 3. the guardrail that must refuse — a domain your [allow] list does not hold.
#    This assumes setup wrote --allow-domain example.com (step 1.2), so a message
#    addressed to the *other* placeholder domain must be refused with exit 3:
mnotify mail send --to someone@contoso.com --subject "should be refused" \
  --body "x" --json
echo "exit=$?"   # expect 3

# 4. one real send, one real channel post, one real DM:
mnotify mail send --to noreply@example.com --subject "final check" --body "hello" --json
mnotify teams send alerts --text "first real post"
mnotify teams send dm --to someone@example.com --text "first real DM"

# 5. what it recorded (bodies and secrets are never recorded, so cannot appear):
mnotify log --tail 10
```

---

## Operator checklist

Copy this into your ticket and tick it. Nothing here may be committed to the repo.

```text
[ ] 1.1  app registration "micro-notify", single tenant — <clientId> recorded
[ ] 1.2  mnotify setup --gen-cert ran on the agent machine (key in keychain)
[ ] 1.3  public certificate uploaded to Entra; thumbprints match
[ ] 1.4  Graph application permission Mail.Send + admin consent granted
[ ] 1.6  mnotify doctor green (config, keychain, token+Mail.Send) — while the consent stands
[ ] 2.1  New-ServicePrincipal created (AppId + Enterprise Object ID)
[ ] 2.2  New-ManagementScope mnotify-noreply filters on the one sender mailbox
[ ] 2.3  New-ManagementRoleAssignment "Application Mail.Send" -CustomResourceScope
[ ] 2.4a Test-ServicePrincipalAuthorization -Resource noreply@…  -> InScope True
[ ] 2.4b Test-ServicePrincipalAuthorization -Resource ops@…      -> InScope False
[ ] 3.2  tenant-wide Entra Mail.Send consent REMOVED (this is the step people skip)
[ ] 3.2b mnotify doctor -> exit 0, green with one warn (token); doctor --send-test
         noreply@example.com delivers one message — never re-consent to silence the warn
[ ] 3.3  mnotify mail send to the scoped mailbox -> exit 0 (consent already removed)
[ ] 3.4  sender override to an out-of-scope mailbox -> HTTP 403, exit 5
[ ] 4.1  one channel workflow per channel, URL stored via teams targets add
[ ] 4.2  the single DM workflow: Post as Flow bot / Chat with Flow bot /
         Recipient triggerBody()?['recipient']
[ ] 4.3  mnotify teams targets list shows every target as "present"
[ ] 5    sender mailbox licensed or shared; Reply-To points at a person
[ ]      allowlist covers the domains your agents really need (empty = all refused)
[ ]      no tenant ID, client ID, mailbox address or webhook URL written into
         any tracked file
```

---

## Rotating the certificate

When Entra warns the credential is near expiry: run `mnotify setup --gen-cert
--force` with the same `--tenant-id` / `--client-id` / `--sender` /
`--allow-domain` values (it replaces the keychain items and rewrites the public
certificate file), upload the new public certificate in Entra, verify the new
thumbprint, then remove the old certificate from the app registration. Check the
swap with `mnotify doctor`: post-step-3 the `token` line is `warn` either way, so an
`AADSTS…` detail is the only `token` failure a rotation problem produces — it means the
new certificate is not accepted (not uploaded, or the thumbprint pair is mismatched).
Any other `token: fail` — "roles claim could not be read", or a `roles` list naming
other roles but not `Mail.Send` — is not a rotation problem: the first is an unexpected
token shape, the second means the tenant-wide consent is back. Confirm end to end
with a real `mnotify mail send`, and keep
the old certificate until that succeeds — Entra accepts several at once.

## Where to look when something fails

| Symptom                                                     | Meaning and fix                                                                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `mnotify: … not implemented yet (design section 8 …)`       | this build predates that command; install the release that has it. Nothing was sent.                                            |
| `mnotify doctor` fails at `config` (exit 2)                 | config unreadable or invalid; the fix hint names the path. `mnotify config show` prints it with secrets masked.                  |
| `doctor` fails at `keychain` (exit 4)                       | a keychain account is missing — re-run `mnotify setup --gen-cert` (or `--auth secret`) on this Mac.                              |
| `doctor` fails at `token` (exit 4), `AADSTS…`               | wrong tenant/client ID, the certificate is not uploaded, or it expired. Check 1.2/1.3.                                           |
| `doctor` `token: warn` (exit 0), "not verifiable from the token"        | **Expected after step 3** — the Entra roles claim is absent by design and proves nothing about the Exchange scoped role. Prove the grant with `mnotify doctor --send-test <addr>` or `mnotify mail send` (3.3); **never** re-grant the tenant-wide consent to silence it. Before step 3: the consent has not propagated yet — 1.4. |
| `doctor` `token: fail` (exit 4), "roles claim could not be read"        | the token is not a readable JWT — an unexpected shape for Entra to produce. Re-run `mnotify doctor`; if it persists, re-check 1.2/1.3 (credential pair) and open an issue with the doctor output (never a token).                                   |
| `doctor` `token: fail` (exit 4), roles listed but no `Mail.Send`        | Entra answered authoritatively and the app does not hold `Mail.Send`. Before step 3: grant admin consent (1.4). After step 3 this is not the steady state — it means tenant-wide app roles are back without `Mail.Send`; undo the re-grant (3.2) and re-check.                                                            |
| `doctor` fails at `teams` (exit 4)                          | a configured target has no URL in the keychain: `mnotify teams targets add <name> --kind <kind>`.                                |
| send refused, exit 3                                        | a guardrail, by design. The message names the recipient or limit. Add the domain to `[allow]` or fix the recipient.              |
| send refused, exit 6                                        | `limits.daily_max` reached for today (UTC). Raise it or wait for the counter to roll over at midnight UTC.                       |
| send fails, exit 5, `HTTP 401`                              | credential problem, not scoping — treat as exit 4 above.                                                                         |
| send fails, exit 5, `HTTP 403` when it should be allowed    | the scoped role does not cover this mailbox: re-check 2.2/2.3 and the `-App` ID in 2.3.                                           |
| send **succeeds** for a mailbox outside the scope           | the tenant-wide Entra consent is still granted, or its cache has not expired. Step 3 is not finished.                             |
| Teams post fails, exit 5, `HTTP 404`/`410`                  | the workflow was deleted or its URL rotated: recreate it and re-run `mnotify teams targets add`.                                  |
| Teams post fails, exit 4, "no webhook URL stored"           | the target exists in config but its keychain account does not — `mnotify teams targets add <name> --kind <kind>`.                 |

## The automated path — `mnotify admin bootstrap`

Everything in steps 1 to 3 above is also runnable as one command:

```sh
mnotify admin bootstrap \
  --sender noreply@example.com \
  --allow-domain example.com
```

The manual path stays the reference, and this section does not replace it: read the
steps you are about to automate, especially [2.4](#24-prove-the-scope-with-the-test-cmdlet)
and [3.1](#31-why-this-step-exists). The command is the same procedure in the same
order, with the portal clicks and the PowerShell pasting removed; what it *cannot*
automate is named at the end of this section, and none of it is hidden.

Run `mnotify admin bootstrap --help` for the flags, and read
[`docs/design/…-design.md`](design/2026-10-27-micro-notify-design.md) §6 for why the
order below is fixed.

### The steps, in order

| # | Step | What happens | Fails with |
| - | ---- | ------------ | ---------- |
| 1 | `preflight` | B1's six read-only checks: `az` on PATH, `az account show` (tenant id/name, signed-in UPN), `memberOf` role check, `pwsh` on PATH, `ExchangeOnlineManagement` present, sender mailbox resolvable. Nothing is written. | exit 2, naming each failing check |
| 2 | `entra-app` | 1.1: find the `micro-notify` app registration **by exact display name**, create it only if absent; same for its service principal. | exit 2 on ambiguity (two same-named apps) |
| 3 | `certificate` | 1.2 + 1.3: generate the key pair (private key to the keychain), upload the public half with `--append --end-date`, then **read the thumbprint back** from the app and compare it with the local one. | exit 2 on mismatch, exit 4 on a keychain problem |
| 4 | `exchange-scope` | 2.1–2.4: one generated PowerShell script run through `pwsh`, doing service principal → management scope → role assignment → the `Test-ServicePrincipalAuthorization` proof for both mailboxes. | exit 2 if the proof does not hold |
| 5 | `config` | Writes `[mail]` (`tenant_id`, `client_id`, `sender`, `auth = "certificate"`) and `[allow]` — the same keys `mnotify setup` writes. | exit 2 if the existing file says something else |
| 6 | `doctor` | `mnotify doctor`, delegated, not re-implemented. | doctor's own exit code |

Order is the contract, and step 5 deliberately comes last: the config advertises a
capability (send as this mailbox) that only exists once step 4 has *proven* it. A
config written before the proof would describe a tenant that cannot honour it, and
`doctor` would still go green on the file alone.

### Run the dry run first

```sh
mnotify admin bootstrap --sender noreply@example.com --allow-domain example.com --dry-run
```

It prints every `az` / `pwsh` command the real run would issue, one per line, executes
nothing, and exits 0. From a fresh tenant:

```
# dry run: every line below is a command that WOULD run; nothing is executed
az account show
az account tenant list
az rest --method GET --uri https://graph.microsoft.com/v1.0/me/memberOf
pwsh -NoProfile -NonInteractive -Command Get-Module -ListAvailable ExchangeOnlineManagement | Select-Object -First 1 -ExpandProperty Version
az ad user show --id noreply@example.com
preflight: dryrun — read-only probes recorded, none executed
az ad app list --display-name micro-notify
az ad app create --display-name micro-notify --sign-in-audience AzureADMyOrg
az ad sp list --filter appId eq '00000000-0000-0000-0000-000000000000'
az ad sp create --id 00000000-0000-0000-0000-000000000000
entra-app: dryrun — would report: created app registration and service principal micro-notify
az ad app credential reset --id 00000000-0000-0000-0000-000000000000 --cert @<public-certificate-path> --append --end-date <certificate-not-after>
certificate: dryrun — planned the upload; no key generated and nothing written to the keychain
pwsh -NoProfile -NonInteractive -File <generated-script-path>
…(the whole generated script is printed, so you can read it before you run it)…
exchange-scope: dryrun — planned the script; no file written or run
config: dryrun — no config file written
doctor: skipped — nothing was changed, so nothing to verify
```

Two things a dry run cannot know, and says so instead of inventing:

- **The ids are placeholders.** `<public-certificate-path>`, `<generated-script-path>`,
  `<certificate-not-after>`, and the all-zero GUIDs are the documented stand-ins. On a
  fresh tenant the plan shows the *creates*, because the canned answers say "not
  found"; against a configured tenant it shows the reads that would find the objects.
- **`doctor` is reported `skipped`, not green.** Nothing was changed, so there is
  nothing to verify. A dry run reports a plan; it does not grade your tenant.

The dry run also works with no `az`, no `pwsh` and no network — that is the point of
reading the plan before you install anything.

### The one step that needs you

Step 4 signs in to Exchange Online with the **device code flow**, and `mnotify` does
not do it for you:

```
mnotify: connecting to Exchange Online (device-code sign-in).
To sign in, use a web browser to open the page https://example.com/devicelogin and enter the code WXYZ123 to authenticate.
```

Open that page, type the code, wait. The line above is printed the moment `pwsh`
emits it, not when the script finishes: the real CLI runs `pwsh` through a streaming
runner, because the sign-in is a wait and a prompt held back until the process exits
is a prompt nobody can act on. If some other capturing runner is in effect, the
command says so up front — so a silent screen is a waiting browser, not a dead
process. `az login` and `Connect-ExchangeOnline` are never run on your behalf.

### Flags

| Flag | Meaning |
| ---- | ------- |
| `--sender ADDR` | required. The one mailbox the app may send from (1.1, 2.2) |
| `--allow-domain DOMAIN` | repeatable. Written to `[allow]`. **The bootstrap refuses to finish with an empty allowlist** — with no allowed recipient every send exits 3, so a "successful" setup would be a broken one |
| `--control-mailbox ADDR` | the negative control for 2.4. Must not be the sender. Default: the address `az` is signed in as |
| `--install-missing` | offer to `brew install` what pre-flight found missing (`azure-cli`, `powershell`). Needs a `y` at a prompt; **refused outright with no terminal** |
| `--force-config` | overwrite an existing config file that says something different |
| `--dry-run` | print the plan, execute nothing, exit 0 |
| `--json` | one machine-readable summary on stdout |
| `--send-test ADDR` | one real test mail at the end, through the normal mail path (spends one unit of the daily cap) |

About `--control-mailbox`: step 2.4 only proves the scope is narrow if a *second*
mailbox comes back `InScope False`. An address that does not resolve also answers
False, so the command resolves it to a real user mailbox first, and it refuses a
sender/control pair that are the same mailbox. If `az` is signed in as the sender,
pass `--control-mailbox` explicitly.

### What it refuses, and with which exit code

| Situation | Result |
| --------- | ------ |
| no `--allow-domain` at all (or `--allow-domain ""`) | exit 2 **before the first probe**, with the fix on the command line |
| pre-flight failed | exit 2 naming each failing check (and `--install-missing` in the hint when a formula would fix it) |
| `--install-missing` with no terminal | exit 2 saying so; `brew` is never reached |
| you answer `n` (or EOF, or a closed pipe) | exit 2, nothing installed, nothing provisioned |
| two app registrations named `micro-notify` | exit 2 naming the object ids; it never picks one |
| the 2.4 proof does not hold | exit 2 — and the config is **not** written |
| `--sender` equals `--control-mailbox` | exit 2 before anything is written |
| existing config holds a different sender/allowlist | exit 2 unless `--force-config` |
| `doctor` fails afterwards | doctor's own exit code (4 keychain/token, 3 guard, 5 remote, 6 daily cap) |

### Re-running it is the normal thing to do

The command looks before it creates at every step, so a re-run on a configured tenant
reports `exists` for all of them and exits 0:

```
preflight: exists — all checks already pass
entra-app: exists — found existing app registration and service principal for micro-notify
certificate: exists — certificate AABBCCDDEEFF… is already uploaded; valid until 2099-01-01T00:00:00Z
exchange-scope: exists — already present: service principal, scope mnotify-noreply and the Application Mail.Send assignment; scope verified for noreply@example.com
config: exists — /Users/you/.config/mnotify/config.toml (unchanged)
doctor: exists — checks green
```

"Exists" means no bytes were written, not a rewrite: the config file is left alone —
including its modification time — when it already says what this run would say, and no
certificate is generated, so the keychain is untouched. It is also safe after a
partial failure: objects created before the failure are found, not duplicated.

A rewrite that *is* needed keeps more than `mnotify setup --force` does. `bootstrap`
owns `[mail]` and `[allow]` only; `[paths]`, the Teams targets **and `[limits]`** are
carried over from the file that is there. `setup --force` resets `[limits]` to the
defaults; a bootstrap re-run is routine maintenance, and quietly dropping your raised
`daily_max` back to 200 during a run that only meant to re-check the tenant would be
an unannounced downgrade.

### `--json`

```sh
mnotify admin bootstrap --sender noreply@example.com --allow-domain example.com --json
```

stdout holds exactly one JSON document; the device-code line, `pwsh`'s output and
doctor's own report are routed to stderr so the document stays parseable:

```json
{
  "ok": true,
  "exitCode": 0,
  "steps": [
    {"name": "preflight", "outcome": "exists", "detail": "all checks already pass"},
    {"name": "entra-app", "outcome": "exists", "detail": "found existing app registration and service principal for micro-notify"},
    {"name": "certificate", "outcome": "exists", "detail": "certificate AABBCCDDEEFF00112233445566778899AABBCCDD is already uploaded; valid until 2099-01-01T00:00:00Z"},
    {"name": "exchange-scope", "outcome": "exists", "detail": "already present: service principal, scope mnotify-noreply and the Application Mail.Send assignment; scope verified for noreply@example.com"},
    {"name": "config", "outcome": "exists", "detail": "/Users/you/.config/mnotify/config.toml (unchanged)"},
    {"name": "doctor", "outcome": "exists", "detail": "checks green"}
  ],
  "sender": "noreply@example.com",
  "allowDomains": ["example.com"],
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "appId": "00000000-0000-0000-0000-000000000000",
  "spObjectId": "ffffffff-ffff-ffff-ffff-ffffffffffff",
  "thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
  "scopeName": "mnotify-noreply",
  "controlMailbox": "admin@contoso.com",
  "configPath": "/Users/you/.config/mnotify/config.toml",
  "doctorExit": 0
}
```

`outcome` is one of `created` (this run made the object), `exists` (it was already
there; this run changed nothing), `dryrun` (planned and printed, not performed) or
`skipped` (the step confirmed nothing — `doctor` reports `skipped` when it is not
green, and its own report above the summary names the failing check). `ok: false` plus
a non-zero `exitCode` means the same thing the exit code means: nothing here can read
as success when it was not.

### What this command never does

- **It never grants an API permission and never grants admin consent.** Nothing in the
  `az` calls it makes touches `requiredResourceAccess`, `appRoles` or a consent grant —
  a tenant-wide grant is exactly what [3.1](#31-why-this-step-exists) exists to get rid
  of, and a command that opened that door while claiming to narrow it would be the
  failure mode this whole procedure is written against. If your tenant needs the
  permission *declared* (1.4) before the Exchange role has force, do 1.4 by hand and
  re-run the bootstrap: it is idempotent, and the re-run reports `exists` everywhere.
- **It never signs you in.** No `az login`, no `Connect-ExchangeOnline`. The device-code
  prompt is yours.
- **It never installs silently.** `brew` runs only behind a `y` at a prompt naming the
  formulae, and the flag is refused when there is no terminal to ask at.
- **It never prints a secret.** No private key, no token, no webhook URL reaches
  stdout, stderr, the config file or the `--json` document. What it prints is account
  names, tenant ids, thumbprints and mailbox addresses — the values this document asks
  you to verify by eye.
- **`--dry-run` changes nothing at all** — not the tenant, not the keychain, not a file.
  The two steps with a local half that bypasses the command runner (the key generation,
  the temporary `.ps1`) refuse a recording runner by design and print their published
  plan instead; replacing your private key during a run that promised to change nothing
  is the bug that rule prevents.

### After it finishes, still yours to do

| Step | Why the command cannot do it |
| ---- | ---------------------------- |
| 1.4 / 3.2 | declaring and then removing the tenant-wide consent is a decision about your tenant's permissions, made in the portal by a human with the right to grant it |
| 2.4's real proof (3.3, 3.4) | `doctor` can read the config and the keychain, but only a **real send** proves the scoped Exchange grant. `--send-test` is the shortest way to run 3.3; 3.4 (a mailbox outside the scope must be refused) still needs you to change the sender by hand |
| Step 4 — Teams targets | each webhook URL is a secret typed at a hidden prompt: `mnotify teams targets add <name> --kind channel\|dm` |
| Step 5 — the mailbox license | a licence assignment is a billing action |

Finish with [Final verification](#final-verification). Expect `token: warn` there — as
that section says, an absent roles claim is what a correctly hardened tenant's token
looks like, and it is not a failure.

---

## The delegated tenant — `mnotify admin bootstrap --mode delegated`

Everything above configures the **app-only** tenant: a certificate credential plus an
Exchange Online scoped role, sending as one mailbox the app is allowed to impersonate.
Design amendment A (see [the design doc](design/2026-10-27-micro-notify-design.md))
adds a second tenant shape for a person to send as: **delegated** mode, where the sender
is the signed-in identity and there is no certificate at all.

`--mode delegated` configures that second shape with the same command, the same
pre-flight, the same find-first app registration, the same config writer and the same
`doctor` at the end. It is not a second command and not a second registration: the app
`bootstrap` finds or creates in step 2 is the one `mnotify login` signs in through, which
is why the delegated flow writes its config *before* the sign-in — `mnotify login` reads
its client id and tenant from `[mail]`, and on a fresh tenant that file does not exist yet.

```sh
mnotify admin bootstrap --sender me@contoso.com --allow-domain contoso.com --mode delegated
```

### The steps, in order

| # | step | what it does |
| - | ---- | ------------ |
| 1 | `preflight` | B1's read-only checks, **minus the two PowerShell ones** (see below) |
| 2 | `entra-app` | the same find-first app registration + service principal as app mode |
| 3 | `delegated-permissions` | declares the five §A.2 delegated scopes on the registration |
| 4 | `public-client-flows` | turns on `isFallbackPublicClient` — the device-code flow's switch |
| 5 | `admin-consent` | optional, opt-in with `--admin-consent`; a refusal warns and continues |
| 6 | `config` | writes `[mail] mode = "delegated"`, sender = your `--sender` |
| 7 | `signin` | `mnotify login`, delegated rather than re-implemented — the device-code flow |
| 8 | `doctor` | the mode-aware delegated checks (token, scopes, who-ami, allow) |

Two steps app mode has and this one does not, and neither is an omission:

- **no certificate** — a delegated send builds no confidential client, so a key uploaded
  here would be a credential the tool never reads;
- **no Exchange scoped role** (steps 2.1–2.4) — the sender is the signed-in person, not a
  mailbox the application impersonates, so there is no recipient scope to bound (§A.3).

For the same reason `--control-mailbox` is not part of this mode, and the two `pwsh`
pre-flight checks are skipped: a route that never calls PowerShell must not be refused by
a machine that cannot run it. App mode still requires both.

### `Allow public client flows` — conditional, and this is the only place it is set

Step 1.4 of this document tells you to leave the portal's **"Allow public client flows"**
toggle at **No**. That instruction is **app-only guidance**, and it stays correct for
every tenant that sends through the certificate + scoped-role route above. Do not change
it there.

The toggle is **Yes** for a delegated tenant, because the device-code flow is a
public-client flow: with the switch off Entra issues the code and then refuses to redeem
it (`invalid_client`), so the sign-in in step 7 can never complete. The value is the
registration-level property `isFallbackPublicClient` — the portal's label, `az ad app
update`'s `--set isFallbackPublicClient=true`, and the Graph property are the same switch.
(Note that `allowPublicClientFlows`, which reads as though it should be the property name,
is not one: it is neither an `az` flag nor a Graph property, and writing it fails.)

Two things follow from it being registration-level rather than mode-level, and both are
why `bootstrap` turns it on only under `--mode delegated`:

- it is **one switch for the whole registration**. A tenant that runs *both* shapes on one
  registration has it on, which is what the delegated half needs and a widening the
  app-only half did not ask for. If you want the two shapes fully separated, use two
  registrations;
- `bootstrap` in app mode **never** touches it. An app-only registration holds a
  certificate credential, and opening such a registration to public-client flows for no
  reason is exactly the kind of silent widening this document exists to prevent.

There is one line of code in this project that sets the property, and it runs only in
delegated mode. `tests/test_admin_delegated.py` pins that from both directions: delegated
mode sets it once, app mode never builds a command that mentions it.

### `--admin-consent`, and why it is allowed to fail

`--admin-consent` requests tenant-wide admin consent for **exactly the five delegated
scopes**, through `az ad app permission grant --scope "Mail.Send ChatMessage.Send
Chat.ReadBasic User.Read offline_access"`.

- It is **not** `az ad app permission admin-consent`. That command consents *every*
  permission the registration declares — including an app-only tenant's `Mail.Send`
  application permission, which is the tenant-wide grant [3.1](#31-why-this-step-exists)
  exists to remove. `bootstrap` never builds it, and a test pins that.
- It **never** adds or removes an application permission. The declared delegated scopes are
  *added* with one `az ad app permission add` per scope (`--api-permissions <id>=Scope`),
  which leaves any `Role` entry on the registration exactly where it was. Neither
  `--set requiredResourceAccess+=` nor a whole-list `--set` is used: az's generic update
  *replaces* the matching resource entry rather than extending it, which would clobber the
  other mode's permissions.
- A **refusal is not a failure.** In a tenant whose verification rules block admin consent
  the command warns, records the step as `skipped` carrying az's reason, and carries on:
  your own `mnotify login` consents those same five scopes for you alone. That is the
  whole reason the flag is opt-in — the tenant-side work is useful whether or not consent
  lands.
- It is **refused outright in app mode** (exit 2), not ignored. An app-only tenant must not
  gain a consented Graph permission, and quietly dropping the flag would leave you
  believing you had consented something.

### The sender must be the person who signs in

In delegated mode the sender is not a mailbox the app reaches; it *is* the identity in the
token (§A.3). So after the sign-in, `bootstrap` compares the signed-in UPN with the
sender it just wrote and **refuses the run** if they differ (exit 2):

```
signed in as somebody.else@contoso.com but this run was asked to configure sender 'me@contoso.com'.
In delegated mode the sender must be the signed-in person (design amendment A.3), so either
`mnotify logout` and sign in again as 'me@contoso.com', or re-run with --sender somebody.else@contoso.com
```

It deliberately does **not** rewrite the config to match the token. You passed `--sender`
on purpose, and a bootstrap quietly changing which mailbox a tool sends from is the sort of
surprise a setup command must not commit.

The sign-in itself is careful about asking twice: a cache-only check (`login --no-prompt`)
runs first, so a re-run on a configured tenant reports `exists` and never opens a browser.
The device-code flow starts only when the cache cannot produce a token — after every
tenant write, so you are asked once, at the point where the tenant is ready for you.

### Delegated mode refuses, and with which exit code

| Situation | Result |
| --------- | ------ |
| `--admin-consent` without `--mode delegated` | exit 2, before the first probe |
| the tenant's Graph service principal does not publish one of the five scopes | exit 2 naming it, **before** any permission is written |
| signed-in UPN is not the configured `--sender` | exit 2, both fixes named; `doctor` is not reached |
| `--admin-consent` refused by the tenant | the step reports `skipped` with the reason; the run still exits 0 |
| no `--allow-domain` at all | exit 2 before the first probe (same guard as app mode) |
| existing config holds a different sender, mode or allowlist | exit 2 unless `--force-config` |

A scope the tenant does not publish is a hard stop rather than a skip: writing a permission
whose id cannot be resolved produces a registration that signs in and then cannot send.

### `--json` for a delegated run

```sh
mnotify admin bootstrap --sender me@contoso.com --allow-domain contoso.com \
  --mode delegated --json
```

```json
{
  "ok": true,
  "exitCode": 0,
  "steps": [
    {"name": "preflight", "outcome": "exists", "detail": "all checks already pass"},
    {"name": "entra-app", "outcome": "exists", "detail": "found existing app registration and service principal for micro-notify"},
    {"name": "delegated-permissions", "outcome": "exists", "detail": "delegated scopes Mail.Send, ChatMessage.Send, Chat.ReadBasic, User.Read, offline_access already declared (nothing to add)"},
    {"name": "public-client-flows", "outcome": "exists", "detail": "isFallbackPublicClient already true — Allow public client flows is on, as amendment A.2 requires for a delegated tenant"},
    {"name": "admin-consent", "outcome": "skipped", "detail": "not requested: pass --admin-consent, or consent per user with `mnotify login`"},
    {"name": "config", "outcome": "exists", "detail": "/Users/you/.config/mnotify/config.toml (unchanged)"},
    {"name": "signin", "outcome": "exists", "detail": "cached delegated sign-in still works"},
    {"name": "doctor", "outcome": "exists", "detail": "checks green"}
  ],
  "mode": "delegated",
  "sender": "me@contoso.com",
  "allowDomains": ["contoso.com"],
  "appId": "00000000-0000-0000-0000-000000000000",
  "delegatedScopes": ["Mail.Send", "ChatMessage.Send", "Chat.ReadBasic", "User.Read", "offline_access"],
  "publicClientFlows": true,
  "signedInAs": "me@contoso.com",
  "configPath": "/Users/you/.config/mnotify/config.toml",
  "doctorExit": 0
}
```

The step list is the same shape app mode prints, and `admin-consent` appears in it even
when it was not requested: the plan `--dry-run` prints and the summary a real run reports
are comparable entry by entry, so `jq` needs no mode-specific handling. There is no
`thumbprint`, `scopeName` or `controlMailbox` key, because a delegated run has no
certificate, no recipient scope and no negative control.

Re-running a configured delegated tenant reports `exists` for the permissions and the
public-client switch and writes nothing: the scope ids and the flag are read back first,
and only what is genuinely missing is written.

### What delegated mode never does

- **Never writes a certificate or a secret**, and never touches `passwordCredentials`.
- **Never grants an application permission** and never runs `admin-consent`. The only
  consent it can request is the five delegated scopes, and only with `--admin-consent`.
- **Never turns on public-client flows in app mode** (above).
- **Never prints a token.** `mnotify login` owns the device-code prompt and the keychain
  write; `bootstrap` reads back only the signed-in UPN (§A.2).
- **Never leaves you signed out.** The point of the mode is that the tenant ends configured
  *and* signed in, so `doctor`'s delegated checks can be green on a fresh tenant.

