use anyhow::Result;
use std::env;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}. Please fill out the .env file in the application directory.")]
    MissingEnv(String),
    
    #[error("Invalid environment variable: {0}. Please check the value in your .env file.")]
    InvalidEnv(String),
}

pub struct Config {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub ssh_key_path: String,
    pub sudo_password: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        
        let ssh_host = env::var("SSH_HOST")
            .map_err(|_| ConfigError::MissingEnv("SSH_HOST".to_string()))?;
        
        if ssh_host.trim().is_empty() {
            return Err(ConfigError::MissingEnv("SSH_HOST (value is empty)".to_string()));
        }
            
        let ssh_port = env::var("SSH_PORT")
            .unwrap_or_else(|_| "22".to_string())
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidEnv("SSH_PORT (must be a valid port number)".to_string()))?;
            
        let ssh_user = env::var("SSH_USER")
            .map_err(|_| ConfigError::MissingEnv("SSH_USER".to_string()))?;
        
        if ssh_user.trim().is_empty() {
            return Err(ConfigError::MissingEnv("SSH_USER (value is empty)".to_string()));
        }
            
        let ssh_key_path = env::var("SSH_KEY_PATH")
            .map_err(|_| ConfigError::MissingEnv("SSH_KEY_PATH".to_string()))?;
        
        if ssh_key_path.trim().is_empty() {
            return Err(ConfigError::MissingEnv("SSH_KEY_PATH (value is empty)".to_string()));
        }
            
        let sudo_password = env::var("SUDO_PASSWORD").ok();
            
        Ok(Self {
            ssh_host,
            ssh_port,
            ssh_user,
            ssh_key_path,
            sudo_password,
        })
    }
}
