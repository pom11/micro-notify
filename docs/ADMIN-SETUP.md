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

`mnotify doctor` reads the role claim from the token it acquires, so once the
consent is gone it will report `Mail.Send` **missing** if you run it before the
Exchange role has propagated. That is the check working, not a regression: the token
is no longer tenant-wide.

Propagate, then test: changes to application permissions and application RBAC are
cached, and that cache is 30 minutes to 2 hours depending on how recently the app
made calls (`Test-ServicePrincipalAuthorization` bypasses the cache; real API calls
do not). If a test in 3.3 or 3.4 contradicts the `Test-ServicePrincipalAuthorization`
output, wait 30 minutes and run it again before you believe the discrepancy.

### 3.3 Positive re-test: the scoped mailbox still sends

```sh
mnotify doctor --send-test noreply@example.com
```

Expect `exit 0`. `--send-test` performs one real send through the normal mail path
(guard, daily counter and audit line included) to the address you pass, and echoes
the recipient masked rather than in full. Then confirm from the audit log:

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

Run these in order. The first three make no network call.

```sh
# 1. config + keychain + Teams targets + token + Mail.Send role:
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
mnotify doctor --send-test noreply@example.com
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
[ ] 1.6  mnotify doctor green (config, keychain, token, Mail.Send role)
[ ] 2.1  New-ServicePrincipal created (AppId + Enterprise Object ID)
[ ] 2.2  New-ManagementScope mnotify-noreply filters on the one sender mailbox
[ ] 2.3  New-ManagementRoleAssignment "Application Mail.Send" -CustomResourceScope
[ ] 2.4a Test-ServicePrincipalAuthorization -Resource noreply@…  -> InScope True
[ ] 2.4b Test-ServicePrincipalAuthorization -Resource ops@…      -> InScope False
[ ] 3.2  tenant-wide Entra Mail.Send consent REMOVED (this is the step people skip)
[ ] 3.3  mnotify doctor --send-test <scoped mailbox> -> exit 0
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
thumbprint, then remove the old certificate from the app registration. `mnotify
doctor` confirms the swap. Keep the old certificate until `mnotify doctor
--send-test` succeeds with the new one — Entra accepts several certificates at once.

## Where to look when something fails

| Symptom                                                     | Meaning and fix                                                                                                                |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `mnotify: … not implemented yet (design section 8 …)`       | this build predates that command; install the release that has it. Nothing was sent.                                            |
| `mnotify doctor` fails at `config` (exit 2)                 | config unreadable or invalid; the fix hint names the path. `mnotify config show` prints it with secrets masked.                  |
| `doctor` fails at `keychain` (exit 4)                       | a keychain account is missing — re-run `mnotify setup --gen-cert` (or `--auth secret`) on this Mac.                              |
| `doctor` fails at `token` (exit 4), `AADSTS…`               | wrong tenant/client ID, the certificate is not uploaded, or it expired. Check 1.2/1.3.                                           |
| `doctor` reports `Mail.Send` missing (exit 4)               | before step 3: grant admin consent (1.4). After step 3: the Exchange role has not propagated — wait 30 min and re-run.           |
| `doctor` fails at `teams` (exit 4)                          | a configured target has no URL in the keychain: `mnotify teams targets add <name> --kind <kind>`.                                |
| send refused, exit 3                                        | a guardrail, by design. The message names the recipient or limit. Add the domain to `[allow]` or fix the recipient.              |
| send refused, exit 6                                        | `limits.daily_max` reached for today (UTC). Raise it or wait for the counter to roll over at midnight UTC.                       |
| send fails, exit 5, `HTTP 401`                              | credential problem, not scoping — treat as exit 4 above.                                                                         |
| send fails, exit 5, `HTTP 403` when it should be allowed    | the scoped role does not cover this mailbox: re-check 2.2/2.3 and the `-App` ID in 2.3.                                           |
| send **succeeds** for a mailbox outside the scope           | the tenant-wide Entra consent is still granted, or its cache has not expired. Step 3 is not finished.                             |
| Teams post fails, exit 5, `HTTP 404`/`410`                  | the workflow was deleted or its URL rotated: recreate it and re-run `mnotify teams targets add`.                                  |
| Teams post fails, exit 4, "no webhook URL stored"           | the target exists in config but its keychain account does not — `mnotify teams targets add <name> --kind <kind>`.                 |
