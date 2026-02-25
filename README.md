# awsh

Launch a disposable EC2 instance and SSH/RDP into it with one command.

```
$ awsh -i ubuntu -p 80,443
$ awsh -i windows
```

Built for cybersecurity students and anyone who needs a quick throwaway box without clicking through the AWS console.

## What it does

1. Validates your AWS credentials
2. Creates (or reuses) a key pair
3. Creates a security group with SSH/RDP open to your IP
4. Launches the instance with the AMI you pick
5. **Linux:** Waits for SSH and drops you into a shell
6. **Windows:** Waits for the admin password, decrypts it, and opens an RDP session via `xfreerdp3`

Everything is tagged `CreatedBy=awsh` so you can clean up with `awsh --terminate`.

## Requirements

- **Linux** (any distro) or **macOS**
- **AWS CLI v2** — [install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **curl** — for public IP detection
- **ssh** — OpenSSH client (for Linux instances)
- **xfreerdp3** — FreeRDP 3 client (for Windows instances) — e.g. `sudo apt install freerdp3-x11`
- **openssl** — for decrypting the Windows admin password

## Install

```bash
curl -sL https://raw.githubusercontent.com/H4R335HR/awsh/main/awsh -o awsh
chmod +x awsh
sudo mv awsh /usr/local/bin/
```

## Usage

```
awsh [options]
awsh --status [--region REGION]
awsh --terminate [--region REGION]
```

| Option | Description | Default |
|---|---|---|
| `-i, --image` | AMI alias or ID | `ubuntu` |
| `-t, --type` | Instance type | `t3.micro` |
| `-p, --ports` | Extra ports to open (comma-separated) | — |
| `-n, --name` | Instance Name tag | `awsh-instance` |
| `-k, --key` | Key pair name | `awsh-key` |
| `--ip` | Custom ingress CIDR | auto-detect |
| `--vpc` | VPC to launch in | default VPC |
| `--subnet` | Subnet to launch in (auto-resolves VPC) | — |
| `--auto-assign-ip` | Auto-assign public IP (for non-default subnets) | — |
| `--no-auto-assign` | Disable auto-assign public IP | — |
| `--user-data` | Bootstrap script (file path or inline) | — |
| `--region` | AWS region override | CLI default |
| `--no-ssh` | Print SSH command instead of connecting (Linux) | — |
| `--no-rdp` | Print RDP info instead of connecting (Windows) | — |
| `--status` | Show all awsh resources + quick connect menu | — |
| `--terminate` | Terminate all awsh instances & clean up | — |
| `--dry-run` | Preview without executing | — |

### Image aliases

| Alias | Resolves to |
|---|---|
| `ubuntu` (default) | Ubuntu 24.04 LTS |
| `ubuntu22` | Ubuntu 22.04 LTS |
| `amazon-linux` / `al2023` | Amazon Linux 2023 |
| `debian` | Debian 12 |
| `rhel` | RHEL 9 |
| `suse` | SLES 15 SP5 |
| `windows` / `win2016` | Windows Server 2016 Base |
| `win2019` | Windows Server 2019 Base |
| `win2022` | Windows Server 2022 Base |
| `ami-xxxxxxxxx` | Any AMI ID directly |

## Examples

```bash
# Defaults — Ubuntu on t3.micro, SSH in
awsh

# Amazon Linux with ports 80 and 443 open
awsh -i amazon-linux -p 80,443

# Bigger instance, custom name
awsh -t t3.small -n pentest-lab

# Windows Server — auto RDP via xfreerdp3
awsh -i windows

# Bootstrap with a setup script
awsh --user-data ./install-tools.sh

# Just create it, don't SSH — prints connection info
awsh --no-ssh

# See all awsh resources (instances, IPs, ports, quick connect)
awsh --status

# Clean up everything
awsh --terminate
```

### Status & Quick Connect

`awsh --status` shows all awsh-created resources with full details:

- **Instances** — public/private IPs, open ports, state
- **Security groups** — IDs and names
- **Key pairs** — with local `.pem` status

Running instances with a valid local key get a **Quick Connect** prompt — press the instance number to SSH in directly.

## Cleanup

`awsh --terminate` finds all resources tagged `CreatedBy=awsh` and:

- Lists instances with confirmation prompt
- Terminates instances
- Deletes security groups (with retries)
- Deletes key pairs and local `.pem` files

## Notes

- Your public IP is auto-detected via `checkip.amazonaws.com`. Override with `--ip`.
- **Linux:** SSH user is auto-resolved from the image (`ubuntu`, `ec2-user`, `admin`) and stored as an instance tag.
- **Windows:** The admin password takes 4-10 minutes after launch. `awsh` decrypts it automatically.
- If a key pair's `.pem` file is left behind from a crashed session (read-only), it is automatically cleaned up on the next run.
- If anything fails mid-launch, the script cleans up the instance, security group, and key pair it created.
- Data is stored in `~/.cache/awsh/` (key files, RDP files).

---

# simplab.py

Automates Simplilearn CloudLabs credential extraction — login, discover lab, LTI launch, and extract cloud credentials (AWS/Azure/GCP) without touching a browser.

## Requirements

```bash
pip install requests
```

## Setup

Save your credentials once so you don't need to pass them every time:

```bash
python simplab.py --email you@example.com --password 'P@ss' --save-creds
```

This writes to `~/.cache/cloudlabs/config.json` (chmod 600, owner-only).

You can also set a default region:

```bash
python simplab.py --email you@example.com --password 'P@ss' --region us-east-1 --save-creds
```

Or use environment variables instead:

```bash
export SIMPLILEARN_EMAIL="you@example.com"
export SIMPLILEARN_PASSWORD="yourpass"
```

**Precedence:** CLI args > env vars > config file.

## Usage

```
python simplab.py [options]
```

| Option | Description | Default |
|---|---|---|
| `--email` | Simplilearn email | config/env |
| `--password` | Simplilearn password | config/env |
| `--eid` | Course elearning ID | `2765` |
| `--lab-index` | Which lab if multiple found | `0` |
| `--configure [PROFILE]` | Configure AWS CLI with lab creds | `default` profile |
| `--region` | Override AWS region for `--configure` | from API |
| `--stop-lab` | Stop/terminate the running lab | — |
| `--save-creds` | Save email/password/region to config file | — |
| `--no-wait` | Don't wait for deployment | — |
| `--timeout` | Deployment timeout in seconds | `300` |
| `--odl-guid` | CloudLabs ODL GUID (skip login) | — |
| `--attendee-guid` | CloudLabs Attendee GUID (skip login) | — |
| `--user-id` | Override Simplilearn numeric user ID | — |
| `--debug` | Save OAuth debug info to disk | — |

## Examples

```bash
# Fetch credentials (uses saved email/password)
python simplab.py

# Fetch and configure AWS CLI (default profile)
python simplab.py --configure

# Fetch and configure a named profile
python simplab.py --configure mylab

# Override region when configuring
python simplab.py --configure --region ap-south-1

# Stop the running lab (uses saved session)
python simplab.py --stop-lab

# Skip login if you already have GUIDs
python simplab.py --odl-guid 3f8790c7-... --attendee-guid 314bfefb-...
```

## How it works

1. **Login** — authenticates to Simplilearn using email/password, gets a JWT session
2. **Discover labs** — fetches available CloudLabs for the given course
3. **LTI Launch** — performs an OAuth 1.0 HMAC-SHA1 signed handoff to CloudLabs
4. **Extract GUIDs** — captures ODL and Attendee GUIDs from the redirect chain
5. **Fetch credentials** — calls the CloudLabs API to get cloud platform credentials

## Stored data

| File | Purpose |
|---|---|
| `~/.cache/cloudlabs/config.json` | Saved email, password, region |
| `~/.cache/cloudlabs/session.json` | Active lab session (for `--stop-lab`) |
| `~/.cache/cloudlabs/lti_debug.txt` | Only on GUID extraction failure |
| `~/.cache/cloudlabs/oauth_debug.txt` | Only with `--debug` |

## License

[MIT](https://github.com/H4R335HR/awsh/blob/main/LICENSE)
