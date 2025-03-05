# Nginx Setup

Meant for use with Debian 11 & 12 systems, automates the installation of nginx and certain configuration files. Does not touch any firewall rules, so you will need to set those manually. This tool has only been tested on Windows 11.

This is extremely early and may not be robust. Use at your own risk.

## Setup

**Configure Connection Details**: A `.env` file will be generated on first run. Edit this file with your SSH connection details:

```
SSH_HOST=your_server_ip
SSH_PORT=22
SSH_USER=your_username
SSH_KEY_PATH=\\path\\to\\your\\openssh_private_key
SUDO_PASSWORD=your_sudo_password
```

## Usage

```
nginx-setup [COMMAND] [OPTIONS]
```

### Available Commands

- `install` - Install Nginx from official repository
- `configure [--config-file <path>]` - Upload and apply custom nginx.conf file
- `create-site <site-name> <domain> [options]` - Create a new site configuration
- `enable-ssl <site-name> <email>` - Enable SSL with Let's Encrypt for an existing site
- `deploy <site-name> <source-folder>` - Deploy local files to a site on the remote server

### Examples

```bash
# Install Nginx
nginx-setup install

# Configure Nginx with a custom configuration file
nginx-setup configure --config-file \\pathto\\nginx.conf

# Create a new site
nginx-setup create-site myblog example.com

# Enable SSL with Let's Encrypt
nginx-setup enable-ssl myblog admin@example.com

# Deploy local files to a remote site
nginx-setup deploy myblog \\path\\to\\local\\files
```

## Workflow

1. Configure the `.env` file with your SSH connection details
2. Run `nginx-setup install` to install Nginx on your server
3. Run `nginx-setup configure` to upload and apply your custom configuration
4. Run `nginx-setup create-site` to create new site configurations
5. Run `nginx-setup enable-ssl` to enable SSL for your sites
6. Run `nginx-setup deploy` to upload your site content to the server

## Notes

- SSL certificates are managed via Let's Encrypt and auto-renewed
- Site directories are created at `/var/www/html/<site-name>`
- Configuration files are stored in `/etc/nginx/sites-available/`
- Custom nginx.conf is uploaded to `/etc/nginx/nginx.conf` when using the configure command
- When deploying, all files from your local directory will be recursively uploaded to the remote site directory
