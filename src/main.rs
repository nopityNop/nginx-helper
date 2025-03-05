use anyhow::{Context, Result};
use clap::{App, Arg, SubCommand};
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
    
    let matches = App::new("Nginx Setup")
        .version("1.0.0")
        .author("[nop,nop,]")
        .about("Setup and configure Nginx on remote Debian 11 & 12 servers")
        .subcommand(SubCommand::with_name("install")
            .about("Install Nginx on the remote server")
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Enable verbose output")))
        .subcommand(SubCommand::with_name("configure")
            .about("Upload and apply custom Nginx configuration")
            .arg(Arg::with_name("config-file")
                .short("c")
                .long("config-file")
                .value_name("FILE")
                .help("Path to the nginx.conf file to upload")
                .default_value("nginx.conf")
                .takes_value(true))
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Enable verbose output")))
        .subcommand(SubCommand::with_name("create-site")
            .about("Create a new site configuration")
            .arg(Arg::with_name("site-name")
                .help("Name of the site (used for directory name)")
                .required(true)
                .index(1))
            .arg(Arg::with_name("domain")
                .help("Domain name for the site")
                .required(true)
                .index(2))
            .arg(Arg::with_name("port")
                .short("p")
                .long("port")
                .help("Port to listen on (default: 80)")
                .takes_value(true))
            .arg(Arg::with_name("enable-ssl")
                .short("s")
                .long("enable-ssl")
                .help("Enable SSL configuration"))
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Enable verbose output")))
        .subcommand(SubCommand::with_name("enable-ssl")
            .about("Enable SSL for an existing site using Let's Encrypt")
            .arg(Arg::with_name("site-name")
                .help("Name of the site to enable SSL for")
                .required(true)
                .index(1))
            .arg(Arg::with_name("email")
                .help("Email address for Let's Encrypt notifications")
                .required(true)
                .index(2)))
        .subcommand(SubCommand::with_name("help")
            .about("Show detailed help information"))
        .get_matches();
    
    match matches.subcommand() {
        ("install", Some(install_matches)) => {
            let verbose = install_matches.is_present("verbose");
            run_install(verbose)
        },
        ("configure", Some(configure_matches)) => {
            let verbose = configure_matches.is_present("verbose");
            let config_file = configure_matches.value_of("config-file").unwrap();
            run_configure(config_file, verbose)
        },
        ("create-site", Some(create_site_matches)) => {
            let site_name = create_site_matches.value_of("site-name").unwrap();
            let domain = create_site_matches.value_of("domain").unwrap();
            let port = create_site_matches.value_of("port").unwrap_or("80");
            let enable_ssl = create_site_matches.is_present("enable-ssl");
            let verbose = create_site_matches.is_present("verbose");
            run_create_site(site_name, domain, port, enable_ssl, verbose)
        },
        ("enable-ssl", Some(enable_ssl_matches)) => {
            let site_name = enable_ssl_matches.value_of("site-name").unwrap();
            let email = enable_ssl_matches.value_of("email").unwrap();
            run_enable_ssl(site_name, email)
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
