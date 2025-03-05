use anyhow::Result;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshError {
    #[error("Failed to connect to SSH server: {0}")]
    ConnectionError(String),
    
    #[error("Authentication failed: {0}")]
    AuthError(String),
    
    #[error("Command execution failed: {0}")]
    CommandError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Sudo requires a password")]
    SudoPasswordRequired,
}

pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub key_path: String,
    pub sudo_password: Option<String>,
}

pub struct CommandResult {
    pub stdout: String,
    pub exit_status: i32,
}

pub struct SshClient {
    config: SshConfig,
    session: Option<Session>,
}

impl SshClient {
    pub fn new(config: SshConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }
    
    pub fn connect(&mut self) -> Result<(), SshError> {
        let tcp = TcpStream::connect(format!("{}:{}", self.config.host, self.config.port))
            .map_err(|e| SshError::ConnectionError(e.to_string()))?;
            
        let mut session = Session::new()
            .map_err(|e| SshError::ConnectionError(e.to_string()))?;
            
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| SshError::ConnectionError(e.to_string()))?;
            
        let key_path = Path::new(&self.config.key_path);
        
        session.userauth_pubkey_file(&self.config.username, None, key_path, None)
            .map_err(|e| SshError::AuthError(e.to_string()))?;
            
        if !session.authenticated() {
            return Err(SshError::AuthError("Authentication failed".to_string()));
        }
        
        self.session = Some(session);
        Ok(())
    }
    
    pub fn execute_command_with_stderr(&self, command: &str) -> Result<CommandResult, SshError> {
        let session = self.session.as_ref()
            .ok_or_else(|| SshError::ConnectionError("Not connected".to_string()))?;
            
        let mut channel = session.channel_session()
            .map_err(|e| SshError::CommandError(e.to_string()))?;
            
        let full_command = format!("{} 2>&1", command);
        channel.exec(&full_command)
            .map_err(|e| SshError::CommandError(e.to_string()))?;
            
        let mut stdout = String::new();
        channel.read_to_string(&mut stdout)
            .map_err(|e| SshError::IoError(e))?;
            
        channel.wait_close()
            .map_err(|e| SshError::CommandError(e.to_string()))?;
            
        let exit_status = channel.exit_status()
            .map_err(|e| SshError::CommandError(e.to_string()))?;
            
        Ok(CommandResult {
            stdout: stdout.clone(),
            exit_status,
        })
    }
    
    pub fn execute_command(&self, command: &str) -> Result<String, SshError> {
        let result = self.execute_command_with_stderr(command)?;
        
        if result.exit_status != 0 {
            return Err(SshError::CommandError(format!(
                "Command exited with status {}: {}", 
                result.exit_status, result.stdout
            )));
        }
        
        Ok(result.stdout)
    }
    
    pub fn execute_sudo_command(&self, command: &str) -> Result<String, SshError> {
        if command.trim().starts_with("sudo") {
            if let Some(sudo_password) = &self.config.sudo_password {
                let sudo_command = format!("echo '{}' | sudo -S {}", sudo_password, &command[5..]);
                return self.execute_command(&sudo_command);
            } else {
                return Err(SshError::SudoPasswordRequired);
            }
        }
        
        self.execute_command(command)
    }
    
    #[allow(dead_code)]
    pub fn disconnect(&mut self) {
        self.session = None;
    }
}
