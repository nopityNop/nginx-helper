use anyhow::Result;
use crate::ssh::SshClient;
use thiserror::Error;
use std::fs;
use std::path::Path;

#[derive(Error, Debug)]
pub enum NginxError {
    #[error("SSH error: {0}")]
    SshError(String),
    
    #[error("Installation error: {0}")]
    InstallationError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Site creation error: {0}")]
    SiteCreationError(String),
    
    #[error("SSL error: {0}")]
    SslError(String),
}

pub struct NginxManager<'a> {
    ssh_client: &'a SshClient,
    verbose: bool,
}

impl<'a> NginxManager<'a> {
    pub fn new(ssh_client: &'a SshClient, verbose: bool) -> Self {
        Self {
            ssh_client,
            verbose,
        }
    }
    
    fn log(&self, message: &str) {
        if self.verbose {
            println!("{}", message);
        }
    }
    
    fn handle_ssh_error(&self, error: &str, context: &str) -> NginxError {
        let error_message = format!("{}: {}", context, error);
        self.log(&error_message);
        NginxError::SshError(error_message)
    }
    
    pub fn install(&self) -> Result<(), NginxError> {
        self.install_prerequisites()?;
        self.install_nginx()?;
        self.start_nginx()?;
        self.verify_running()?;
        Ok(())
    }
    
    fn install_prerequisites(&self) -> Result<(), NginxError> {
        println!("Installing prerequisites...");
        
        self.log("Executing command: sudo apt update");
        match self.ssh_client.execute_sudo_command("sudo apt update") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to update package lists"));
            }
        }
        
        Ok(())
    }
    
    fn install_nginx(&self) -> Result<(), NginxError> {
        println!("Installing Nginx...");
        
        self.log("Executing command: sudo apt install -y nginx");
        match self.ssh_client.execute_sudo_command("sudo apt install -y nginx") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to install Nginx"));
            }
        }
        
        self.log("Executing command: sudo nginx -v");
        match self.ssh_client.execute_sudo_command("sudo nginx -v") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
                
                if !output.contains("nginx version") {
                    return Err(NginxError::InstallationError(
                        "Nginx installation verification failed: Version information not found".to_string()
                    ));
                }
                
                println!("Nginx installed successfully: {}", output.trim());
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to verify Nginx installation"));
            }
        }
        
        Ok(())
    }
    
    fn start_nginx(&self) -> Result<(), NginxError> {
        println!("Starting Nginx service...");
        
        self.log("Executing command: sudo systemctl start nginx");
        match self.ssh_client.execute_sudo_command("sudo systemctl start nginx") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to start Nginx service"));
            }
        }
        
        self.log("Executing command: sudo systemctl enable nginx");
        match self.ssh_client.execute_sudo_command("sudo systemctl enable nginx") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to enable Nginx service"));
            }
        }
        
        Ok(())
    }
    
    fn verify_running(&self) -> Result<(), NginxError> {
        println!("Verifying Nginx is running...");
        
        self.log("Executing command: curl -I 127.0.0.1");
        match self.ssh_client.execute_command("curl -I 127.0.0.1") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
                
                if !output.contains("Server: nginx") {
                    return Err(NginxError::InstallationError(
                        "Nginx does not appear to be running correctly".to_string()
                    ));
                }
                
                println!("Nginx installed and running successfully!");
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to verify Nginx is running"));
            }
        }
        
        Ok(())
    }
    
    pub fn upload_config(&self, config_file_path: &str) -> Result<(), NginxError> {
        println!("Uploading Nginx configuration...");
        
        let config_path = Path::new(config_file_path);
        let config_content = match fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => {
                return Err(NginxError::ConfigurationError(format!(
                    "Failed to read configuration file: {}", e
                )));
            }
        };
        
        let escaped_content = config_content.replace("'", "'\\''");
        let temp_file = "/tmp/nginx.conf";
        
        self.log(format!("Creating temporary configuration file at {}", temp_file).as_str());
        let create_temp_cmd = format!("echo '{}' > {}", escaped_content, temp_file);
        match self.ssh_client.execute_command(&create_temp_cmd) {
            Ok(_) => {},
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to create temporary configuration file"));
            }
        }
        
        self.log("Moving configuration file to /etc/nginx/nginx.conf");
        match self.ssh_client.execute_sudo_command(&format!("sudo mv {} /etc/nginx/nginx.conf", temp_file)) {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to move configuration file"));
            }
        }
        
        self.log("Setting correct permissions on configuration file");
        match self.ssh_client.execute_sudo_command("sudo chown root:root /etc/nginx/nginx.conf && sudo chmod 644 /etc/nginx/nginx.conf") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to set permissions on configuration file"));
            }
        }
        
        println!("Nginx configuration uploaded successfully!");
        
        Ok(())
    }
    
    pub fn test_config(&self) -> Result<(), NginxError> {
        println!("Testing Nginx configuration...");
        
        self.log("Executing command: sudo nginx -t");
        match self.ssh_client.execute_sudo_command("sudo nginx -t") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
                
                if !output.contains("test is successful") {
                    return Err(NginxError::ConfigurationError(format!(
                        "Nginx configuration test failed: {}", output
                    )));
                }
                
                println!("Nginx configuration test successful!");
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to test Nginx configuration"));
            }
        }
        
        Ok(())
    }
    
    pub fn reload(&self) -> Result<(), NginxError> {
        println!("Reloading Nginx...");
        
        self.log("Executing command: sudo nginx -s reload");
        match self.ssh_client.execute_sudo_command("sudo nginx -s reload") {
            Ok(output) => {
                if self.verbose {
                    println!("Output: {}", output);
                }
                
                println!("Nginx reloaded successfully!");
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to reload Nginx"));
            }
        }
        
        Ok(())
    }
    
    pub fn create_site(&self, site_name: &str, domain: &str, port: &str, enable_ssl: bool) -> Result<(), NginxError> {
        println!("Creating site configuration for {}...", domain);
        
        if site_name.is_empty() || domain.is_empty() {
            return Err(NginxError::SiteCreationError(
                "Site name and domain cannot be empty".to_string()
            ));
        }
        
        if port.parse::<u16>().is_err() {
            return Err(NginxError::SiteCreationError(
                format!("Invalid port number: {}", port)
            ));
        }
        
        let site_dir = format!("/var/www/html/{}", site_name);
        self.log(&format!("Creating site directory: {}", site_dir));
        
        match self.ssh_client.execute_sudo_command(&format!("sudo mkdir -p {}", site_dir)) {
            Ok(_) => self.log("Site directory created successfully"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to create site directory"));
            }
        }
        
        match self.ssh_client.execute_sudo_command(&format!("sudo chown -R www-data:www-data {}", site_dir)) {
            Ok(_) => self.log("Directory permissions set"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to set directory permissions"));
            }
        }
        
        let sample_html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Welcome to {}</title>
    <style>
        body {{
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }}
    </style>
</head>
<body>
    <h1>Welcome to {}!</h1>
    <p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>
    
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    
    <p><em>Thank you for using nginx.</em></p>
</body>
</html>"#, domain, domain);
        
        let escaped_html = sample_html.replace("\"", "\\\"").replace("$", "\\$");
        
        let temp_file = "/tmp/temp_index.html";
        
        let create_temp_cmd = format!(
            "echo \"{}\" > {}",
            escaped_html, temp_file
        );
        
        match self.ssh_client.execute_command(&create_temp_cmd) {
            Ok(_) => self.log("Created temporary index.html"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to create temporary index.html"));
            }
        }
        
        match self.ssh_client.execute_sudo_command(&format!("sudo mv {} {}/index.html", temp_file, site_dir)) {
            Ok(_) => self.log("Moved index.html to site directory"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to move index.html to site directory"));
            }
        }
        
        match self.ssh_client.execute_sudo_command(&format!("sudo chown www-data:www-data {}/index.html", site_dir)) {
            Ok(_) => self.log("File permissions set"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to set file permissions"));
            }
        }
        
        let site_config = format!(r#"server {{
    listen {port};
    listen [::]:{port};

    server_name {domain};

    root {site_dir};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ =404;
    }}

    # Additional settings
    # Enable gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;

    # Add security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    # For SSL configuration, use the enable-ssl command
    # Example: nginx-setup enable-ssl {site_name} your-email@example.com
}}"#);
        
        let config_file = format!("/tmp/{}.conf", site_name);
        let create_config_cmd = format!(
            "echo \"{}\" > {}",
            site_config.replace("\"", "\\\"").replace("$", "\\$"), config_file
        );
        
        match self.ssh_client.execute_command(&create_config_cmd) {
            Ok(_) => self.log("Created temporary site configuration file"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to create temporary site configuration"));
            }
        }
        
        let sites_available = format!("/etc/nginx/sites-available/{}", site_name);
        match self.ssh_client.execute_sudo_command(&format!("sudo mv {} {}", config_file, sites_available)) {
            Ok(_) => self.log("Moved configuration to sites-available"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to move configuration to sites-available"));
            }
        }
        
        let sites_enabled = format!("/etc/nginx/sites-enabled/{}", site_name);
        match self.ssh_client.execute_sudo_command(&format!("sudo ln -sf {} {}", sites_available, sites_enabled)) {
            Ok(_) => self.log("Created symlink in sites-enabled"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to create symlink in sites-enabled"));
            }
        }
        
        match self.ssh_client.execute_sudo_command("sudo nginx -t") {
            Ok(_) => self.log("Nginx configuration test successful"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Nginx configuration test failed"));
            }
        }
        
        match self.ssh_client.execute_sudo_command("sudo systemctl reload nginx") {
            Ok(_) => self.log("Nginx reloaded successfully"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to reload nginx"));
            }
        }
        
        if enable_ssl {
            println!("Note: SSL flag was provided, but we now use Let's Encrypt via a separate command.");
            println!("To enable SSL for this site, please use: nginx-setup enable-ssl {} your-email@example.com", site_name);
        }
        
        Ok(())
    }
    
    pub fn enable_ssl(&self, site_name: &str, email: &str) -> Result<(), NginxError> {
        println!("Enabling SSL for site {} using Let's Encrypt...", site_name);
        
        let site_config_path = format!("/etc/nginx/sites-available/{}", site_name);
        match self.ssh_client.execute_command(&format!("test -f {} && echo exists", site_config_path)) {
            Ok(output) => {
                if !output.contains("exists") {
                    return Err(NginxError::SslError(format!(
                        "Site configuration not found: {}", site_config_path
                    )));
                }
                self.log("Site configuration found");
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to check if site configuration exists"));
            }
        }
        
        self.log("Checking if certbot is installed...");
        match self.ssh_client.execute_sudo_command("sudo which certbot || echo 'not-installed'") {
            Ok(output) => {
                if output.contains("not-installed") {
                    self.log("Certbot not found, installing...");
                    
                    match self.ssh_client.execute_sudo_command("sudo apt-get update") {
                        Ok(_) => self.log("Package lists updated"),
                        Err(e) => {
                            return Err(self.handle_ssh_error(&e.to_string(), "Failed to update package lists"));
                        }
                    }
                    
                    match self.ssh_client.execute_sudo_command("sudo apt-get install -y certbot python3-certbot-nginx") {
                        Ok(_) => self.log("Certbot installed successfully"),
                        Err(e) => {
                            return Err(self.handle_ssh_error(&e.to_string(), "Failed to install certbot"));
                        }
                    }
                } else {
                    self.log("Certbot is already installed");
                }
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to check if certbot is installed"));
            }
        }
        
        let extract_domain_cmd = format!(
            "grep -oP 'server_name \\K[^;]+' {} || echo 'domain-not-found'",
            site_config_path
        );
        
        let domain = match self.ssh_client.execute_sudo_command(&extract_domain_cmd) {
            Ok(output) => {
                let domain = output.trim();
                if domain == "domain-not-found" || domain.is_empty() {
                    return Err(NginxError::SslError(
                        "Could not find server_name in the site configuration".to_string()
                    ));
                }
                domain.to_string()
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to extract domain from site configuration"));
            }
        };
        
        self.log(&format!("Found domain in site configuration: {}", domain));
        
        self.log("Running certbot to obtain SSL certificate...");
        let certbot_cmd = format!(
            "sudo certbot --nginx -d {} --non-interactive --agree-tos --email {} --redirect",
            domain.trim(), email
        );
        
        match self.ssh_client.execute_sudo_command(&certbot_cmd) {
            Ok(output) => {
                self.log("Certbot ran successfully");
                println!("Certbot output:");
                println!("{}", output);
            },
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to run certbot"));
            }
        }
        
        match self.ssh_client.execute_sudo_command("sudo nginx -t") {
            Ok(_) => self.log("Nginx configuration test successful"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Nginx configuration test failed after SSL setup"));
            }
        }
        
        match self.ssh_client.execute_sudo_command("sudo systemctl reload nginx") {
            Ok(_) => self.log("Nginx reloaded successfully"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to reload nginx"));
            }
        }
        
        self.log("Ensuring certbot renewal service is enabled...");
        match self.ssh_client.execute_sudo_command("sudo systemctl enable certbot.timer && sudo systemctl start certbot.timer") {
            Ok(_) => self.log("Certbot renewal service enabled"),
            Err(e) => {
                return Err(self.handle_ssh_error(&e.to_string(), "Failed to enable certbot renewal service"));
            }
        }
        
        println!("SSL has been successfully enabled for site {}!", site_name);
        println!("Certificates will be automatically renewed before they expire.");
        
        Ok(())
    }
}
