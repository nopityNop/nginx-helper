use anyhow::{Context, Result};
use clap::{Command, Arg};
use std::path::Path;
use std::fs;
use std::env;
use std::io::Write;
use dotenv;

mod config;
mod ssh;
mod nginx;

use config::Config;
use ssh::{SshClient, SshConfig};
use nginx::NginxManager;

fn main() -> Result<()> {
    ensure_env_file_exists()?;
    
    dotenv::from_path(".env").ok();
    
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help") {
        print_detailed_help();
        return Ok(());
    }
    
    let matches = Command::new("Nginx Setup")
        .version("1.0.0")
        .author("[nop,nop,]")
        .about("Setup and configure Nginx on remote Debian 11 & 12 servers")
        .subcommand(Command::new("install")
            .about("Install Nginx on the remote server")
            .arg(Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)))
        .subcommand(Command::new("configure")
            .about("Upload and apply custom Nginx configuration")
            .arg(Arg::new("config-file")
                .short('c')
                .long("config-file")
                .value_name("FILE")
                .help("Path to the nginx.conf file to upload")
                .default_value("nginx.conf"))
            .arg(Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)))
        .subcommand(Command::new("create-site")
            .about("Create a new site configuration")
            .arg(Arg::new("site-name")
                .help("Name of the site (used for directory name)")
                .required(true)
                .index(1))
            .arg(Arg::new("domain")
                .help("Domain name for the site")
                .required(true)
                .index(2))
            .arg(Arg::new("port")
                .short('p')
                .long("port")
                .help("Port to listen on (default: 80)")
                .value_parser(clap::value_parser!(String)))
            .arg(Arg::new("enable-ssl")
                .short('s')
                .long("enable-ssl")
                .help("Enable SSL configuration")
                .action(clap::ArgAction::SetTrue))
            .arg(Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)))
        .subcommand(Command::new("enable-ssl")
            .about("Enable SSL for an existing site using Let's Encrypt")
            .arg(Arg::new("site-name")
                .help("Name of the site to enable SSL for")
                .required(true)
                .index(1))
            .arg(Arg::new("email")
                .help("Email address for Let's Encrypt notifications")
                .required(true)
                .index(2)))
        .subcommand(Command::new("deploy")
            .about("Deploy local files to a remote site")
            .arg(Arg::new("site-name")
                .help("Name of the site to deploy to (directory in /var/www/html/)")
                .required(true)
                .index(1))
            .arg(Arg::new("source-folder")
                .help("Local source folder to deploy")
                .required(true)
                .index(2))
            .arg(Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)))
        .subcommand(Command::new("help")
            .about("Show detailed help information"))
        .get_matches();
    
    match matches.subcommand() {
        Some(("install", install_matches)) => {
            let verbose = install_matches.contains_id("verbose");
            run_install(verbose)
        },
        Some(("configure", configure_matches)) => {
            let verbose = configure_matches.contains_id("verbose");
            let config_file = configure_matches.get_one::<String>("config-file").unwrap();
            run_configure(config_file, verbose)
        },
        Some(("create-site", create_site_matches)) => {
            let site_name = create_site_matches.get_one::<String>("site-name").unwrap();
            let domain = create_site_matches.get_one::<String>("domain").unwrap();
            let default_port = String::from("80");
            let port = create_site_matches.get_one::<String>("port").unwrap_or(&default_port);
            let enable_ssl = create_site_matches.contains_id("enable-ssl");
            let verbose = create_site_matches.contains_id("verbose");
            run_create_site(site_name, domain, port, enable_ssl, verbose)
        },
        Some(("enable-ssl", enable_ssl_matches)) => {
            let site_name = enable_ssl_matches.get_one::<String>("site-name").unwrap();
            let email = enable_ssl_matches.get_one::<String>("email").unwrap();
            run_enable_ssl(site_name, email)
        },
        Some(("deploy", deploy_matches)) => {
            let site_name = deploy_matches.get_one::<String>("site-name").unwrap();
            let source_folder = deploy_matches.get_one::<String>("source-folder").unwrap();
            let verbose = deploy_matches.contains_id("verbose");
            run_deploy(site_name, source_folder, verbose)
        },
        _ => {
            println!("No valid subcommand provided. Use --help for usage information.");
            Ok(())
        }
    }
}

fn print_detailed_help() {
    println!("Nginx Setup Tool v0.1.0");
    println!("========================");
    println!("\nDESCRIPTION:");
    println!("  Meant for use with Debian 11 & 12 systems, automates the installation");
    println!("  of Nginx and certain configuration files. Does not touch any firewall");
    println!("  rules, so you will need to set those manually.");
    println!("\nCONFIGURATION:");
    println!("  The tool uses environment variables loaded from a .env file in the same");
    println!("  directory as the executable. The following variables are required:");
    println!();
    println!("  SSH_HOST      IP address or hostname of the remote server");
    println!("  SSH_PORT      SSH port (default: 22)");
    println!("  SSH_USER      SSH username for the connection");
    println!("  SSH_KEY_PATH  Path to the SSH private key file");
    println!("  SUDO_PASSWORD Password for sudo operations (optional)");
    println!("\nCOMMANDS:");
    println!("  install                 Install Nginx on the remote server");
    println!("    Options:");
    println!("      -v, --verbose       Show detailed output during installation");
    println!();
    println!("  configure [options]     Upload and apply custom Nginx configuration");
    println!("    Options:");
    println!("      -c, --config-file <FILE>   Path to the nginx.conf file to upload");
    println!("                                 Default: nginx.conf in current directory");
    println!("      -v, --verbose              Show detailed output during configuration");
    println!();
    println!("  create-site [options]    Create a new site configuration");
    println!("    Options:");
    println!("      <site-name>            Name of the site (used for directory name)");
    println!("      <domain>               Domain name for the site");
    println!("      -p, --port <PORT>      Port to listen on (default: 80)");
    println!("      -s, --enable-ssl       Enable SSL configuration");
    println!("      -v, --verbose          Show detailed output during site creation");
    println!();
    println!("  enable-ssl [options]     Enable SSL for an existing site using Let's Encrypt");
    println!("    Options:");
    println!("      <site-name>            Name of the site to enable SSL for");
    println!("      <email>                Email address for Let's Encrypt notifications");
    println!();
    println!("  deploy [options]         Deploy local files to a remote site");
    println!("    Options:");
    println!("      <site-name>            Name of the site to deploy to (directory in /var/www/html/)");
    println!("      <source-folder>        Local source folder to deploy");
    println!("      -v, --verbose          Show detailed output during deployment");
    println!();
    println!("  --help, -h, help        Show this help information");
    println!();
    println!("NOTE: For examples and a detailed workflow, please refer to the README.md file.");
}

fn run_install(verbose: bool) -> Result<()> {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            eprintln!("\nPlease edit the .env file in the application directory with your SSH connection details.");
            eprintln!("For help, run: nginx-setup help");
            return Err(e.into());
        }
    };
    
    println!("Connecting to {}:{} as {}", config.ssh_host, config.ssh_port, config.ssh_user);
    
    let ssh_config = SshConfig {
        host: config.ssh_host,
        port: config.ssh_port,
        username: config.ssh_user,
        key_path: config.ssh_key_path,
        sudo_password: config.sudo_password,
    };
    
    let mut ssh_client = SshClient::new(ssh_config);
    
    ssh_client.connect()
        .context("Failed to connect to SSH server")?;
        
    println!("Successfully connected to SSH server!");
    
    // Check if sudo is installed
    println!("Checking if sudo is installed...");
    let sudo_check_result = ssh_client.execute_command("which sudo");
    let sudo_installed = match sudo_check_result {
        Ok(output) => !output.trim().is_empty(),
        Err(_) => false,
    };
    
    if !sudo_installed {
        eprintln!("Error: 'sudo' is not installed on the remote server.");
        eprintln!("Please install sudo manually before continuing:");
        eprintln!("  1. Log in to the server as root");
        eprintln!("  2. Run: apt-get update && apt-get install -y sudo");
        eprintln!("  3. Run this command again");
        return Err(anyhow::anyhow!("sudo not installed on remote server"));
    }
    println!("sudo is installed.");
    
    // Check if curl is installed
    println!("Checking if curl is installed...");
    let curl_check_result = ssh_client.execute_command("which curl");
    let curl_installed = match curl_check_result {
        Ok(output) => !output.trim().is_empty(),
        Err(_) => false,
    };
    
    if !curl_installed {
        println!("curl is not installed. Installing curl...");
        // Use noninteractive frontend to avoid prompts
        match ssh_client.execute_sudo_command("DEBIAN_FRONTEND=noninteractive apt-get update") {
            Ok(_) => {
                println!("APT repository updated.");
                match ssh_client.execute_sudo_command("DEBIAN_FRONTEND=noninteractive apt-get install -y curl") {
                    Ok(_) => println!("curl has been successfully installed."),
                    Err(e) => {
                        eprintln!("Error installing curl: {}", e);
                        return Err(anyhow::anyhow!("Failed to install curl: {}", e));
                    }
                }
            },
            Err(e) => {
                eprintln!("Error updating APT repository: {}", e);
                return Err(anyhow::anyhow!("Failed to update APT: {}", e));
            }
        }
    } else {
        println!("curl is already installed.");
    }
    
    let nginx_manager = NginxManager::new(&ssh_client, verbose);
    
    if let Err(e) = nginx_manager.install() {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    Ok(())
}

fn run_configure(config_file: &str, verbose: bool) -> Result<()> {
    let config_path = Path::new(config_file);
    if !config_path.exists() {
        eprintln!("Error: Configuration file '{}' not found", config_file);
        return Err(anyhow::anyhow!("Configuration file not found"));
    }
    
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            eprintln!("\nPlease edit the .env file in the application directory with your SSH connection details.");
            eprintln!("For help, run: nginx-setup help");
            return Err(e.into());
        }
    };
    
    println!("Connecting to {}:{} as {}", config.ssh_host, config.ssh_port, config.ssh_user);
    
    let ssh_config = SshConfig {
        host: config.ssh_host,
        port: config.ssh_port,
        username: config.ssh_user,
        key_path: config.ssh_key_path,
        sudo_password: config.sudo_password,
    };
    
    let mut ssh_client = SshClient::new(ssh_config);
    
    ssh_client.connect()
        .context("Failed to connect to SSH server")?;
        
    println!("Successfully connected to SSH server!");
    
    let nginx_manager = NginxManager::new(&ssh_client, verbose);
    
    if let Err(e) = nginx_manager.upload_config(config_file) {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    if let Err(e) = nginx_manager.test_config() {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    if let Err(e) = nginx_manager.reload() {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    println!("Nginx configuration applied and service reloaded successfully!");
    
    Ok(())
}

fn run_create_site(site_name: &str, domain: &str, port: &str, enable_ssl: bool, verbose: bool) -> Result<()> {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            eprintln!("\nPlease edit the .env file in the application directory with your SSH connection details.");
            eprintln!("For help, run: nginx-setup help");
            return Err(e.into());
        }
    };
    
    println!("Connecting to {}:{} as {}", config.ssh_host, config.ssh_port, config.ssh_user);
    
    let ssh_config = SshConfig {
        host: config.ssh_host,
        port: config.ssh_port,
        username: config.ssh_user,
        key_path: config.ssh_key_path,
        sudo_password: config.sudo_password,
    };
    
    let mut ssh_client = SshClient::new(ssh_config);
    
    ssh_client.connect()
        .context("Failed to connect to SSH server")?;
        
    println!("Successfully connected to SSH server!");
    
    let nginx_manager = NginxManager::new(&ssh_client, verbose);
    
    if let Err(e) = nginx_manager.create_site(site_name, domain, port, enable_ssl) {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    println!("Site configuration created successfully!");
    
    Ok(())
}

fn run_enable_ssl(site_name: &str, email: &str) -> Result<()> {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            eprintln!("\nPlease edit the .env file in the application directory with your SSH connection details.");
            eprintln!("For help, run: nginx-setup help");
            return Err(e.into());
        }
    };
    
    println!("Connecting to {}:{} as {}", config.ssh_host, config.ssh_port, config.ssh_user);
    
    let ssh_config = SshConfig {
        host: config.ssh_host,
        port: config.ssh_port,
        username: config.ssh_user,
        key_path: config.ssh_key_path,
        sudo_password: config.sudo_password,
    };
    
    let mut ssh_client = SshClient::new(ssh_config);
    
    ssh_client.connect()
        .context("Failed to connect to SSH server")?;
        
    println!("Successfully connected to SSH server!");
    
    let nginx_manager = NginxManager::new(&ssh_client, false);
    
    if let Err(e) = nginx_manager.enable_ssl(site_name, email) {
        eprintln!("Error: {}", e);
        return Err(e.into());
    }
    
    println!("SSL enabled successfully for {}!", site_name);
    
    Ok(())
}

fn run_deploy(site_name: &str, source_folder: &str, verbose: bool) -> Result<()> {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            eprintln!("\nPlease edit the .env file in the application directory with your SSH connection details.");
            eprintln!("For help, run: nginx-setup help");
            return Err(e.into());
        }
    };
    
    if verbose {
        println!("Connecting to {}:{} as {}", config.ssh_host, config.ssh_port, config.ssh_user);
    }
    
    let username = config.ssh_user.clone();
    
    let ssh_config = SshConfig {
        host: config.ssh_host,
        port: config.ssh_port,
        username: config.ssh_user,
        key_path: config.ssh_key_path,
        sudo_password: config.sudo_password,
    };
    
    let mut ssh_client = SshClient::new(ssh_config);
    
    ssh_client.connect()
        .context("Failed to connect to SSH server")?;
        
    if verbose {
        println!("Successfully connected to SSH server!");
    }
    
    let source_path = Path::new(source_folder);
    if !source_path.exists() || !source_path.is_dir() {
        return Err(anyhow::anyhow!("Source folder does not exist or is not a directory: {}", source_folder));
    }
    
    let remote_path = format!("/var/www/html/{}", site_name);
    
    if verbose {
        println!("Ensuring remote directory exists: {}", remote_path);
    }
    
    ssh_client.execute_sudo_command(&format!("mkdir -p {}", remote_path))
        .context("Failed to create remote directory")?;
        
    if verbose {
        println!("Setting correct permissions on remote directory");
    }
    
    ssh_client.execute_sudo_command(&format!("chown -R {} {}", username, remote_path))
        .context("Failed to set ownership")?;
        
    if verbose {
        println!("Uploading files from {} to {}", source_folder, remote_path);
    }
    
    ssh_client.upload_directory(source_folder, &remote_path)
        .context("Failed to upload files")?;
        
    if verbose {
        println!("Setting permissions on uploaded files");
    }
    
    ssh_client.execute_sudo_command(&format!("find {} -type d -exec chmod 755 {{}} \\;", remote_path))
        .context("Failed to set directory permissions")?;
        
    ssh_client.execute_sudo_command(&format!("find {} -type f -exec chmod 644 {{}} \\;", remote_path))
        .context("Failed to set file permissions")?;
        
    println!("Successfully deployed site {} from {} to {}", site_name, source_folder, remote_path);
    
    Ok(())
}

fn ensure_env_file_exists() -> Result<()> {
    let exe_path = env::current_exe().context("Failed to get executable path")?;
    let exe_dir = exe_path.parent().context("Failed to get executable directory")?;
    let env_file_path = exe_dir.join(".env");
    
    if !env_file_path.exists() {
        println!("No .env file found in the executable directory.");
        println!("Creating .env file at: {}", env_file_path.display());
        let mut file = fs::File::create(&env_file_path)?;
        let template = r#"SSH_HOST=your_server_ip
SSH_PORT=22
SSH_USER=your_username
SSH_KEY_PATH=/path/to/your/openssh_private_key
SUDO_PASSWORD=your_sudo_password
"#;
        file.write_all(template.as_bytes())?;
        println!("Created .env file with template values.");
        println!("Please edit the .env file with your SSH connection details before running again.");
    }
    
    dotenv::from_path(&env_file_path).ok();
    
    Ok(())
}
