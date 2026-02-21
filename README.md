# awsh

Launch a disposable EC2 instance and SSH into it with one command.

```
$ awsh -i ubuntu -p 80,443
```

Built for cybersecurity students and anyone who needs a quick throwaway box without clicking through the AWS console or running 6 CLI commands.

## What it does

1. Validates your AWS credentials
2. Creates (or reuses) a key pair
3. Creates a security group with SSH open to your IP
4. Launches the instance with the AMI you pick
5. Waits for SSH and drops you into a shell

Everything is tagged `CreatedBy=awsh` so you can clean up with `awsh --terminate`.

## Requirements

- **Linux** (any distro) or **macOS** — this is a Bash script, not tested on Windows
- **AWS CLI v2** — [install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **curl** — for public IP detection via `checkip.amazonaws.com`
- **ssh** — OpenSSH client

The script checks for all required dependencies at startup and exits with a clear error if anything is missing.

## Install

```bash
curl -sL https://raw.githubusercontent.com/H4R335HR/awsh/main/awsh -o awsh
chmod +x awsh
sudo mv awsh /usr/local/bin/
```

## Usage

```
awsh [options]
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
| `--user-data` | Bootstrap script (file path or inline) | — |
| `--region` | AWS region override | CLI default |
| `--no-ssh` | Print SSH command instead of connecting | — |
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
| `ami-xxxxxxxxx` | Any AMI ID directly |

## Examples

```bash
# Defaults — Ubuntu on t3.micro, SSH in
awsh

# Amazon Linux with ports 80 and 443 open
awsh -i amazon-linux -p 80,443

# Bigger instance, custom name
awsh -t t3.small -n pentest-lab

# Bootstrap with a setup script
awsh --user-data ./install-tools.sh

# Inline bootstrap
awsh --user-data '#!/bin/bash
apt update && apt install -y nmap nikto'

# Just create it, don't SSH
awsh --no-ssh

# Clean up everything
awsh --terminate
```

## How cleanup works

`awsh --terminate` finds all resources tagged `CreatedBy=awsh` and:

- Lists instances with confirmation prompt
- Terminates instances
- Deletes security groups (with retries)
- Deletes key pairs and local `.pem` files

## Notes

- Your public IP is auto-detected via `checkip.amazonaws.com`. Override with `--ip`.
- The SSH user is auto-resolved from the image (`ubuntu`, `ec2-user`, `admin`).
- If the key pair exists in AWS and the local `.pem` is present, it's reused. If the `.pem` is missing, the key is recreated.
- If anything fails mid-launch, the script automatically cleans up the instance, security group, and key pair it created.

## License

[MIT](https://github.com/H4R335HR/awsh/blob/main/LICENSE)
