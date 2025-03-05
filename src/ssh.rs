use anyhow::Result;
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use thiserror::Error;
use std::fs;
use std::io::Write;

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
    
    #[error("File transfer error: {0}")]
    FileTransferError(String),
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
        let cmd = command.trim();
        
        if let Some(sudo_password) = &self.config.sudo_password {
            let sudo_cmd = if cmd.starts_with("sudo ") {
                format!("echo '{}' | sudo -S {}", sudo_password, &cmd[5..])
            } else {
                format!("echo '{}' | sudo -S {}", sudo_password, cmd)
            };
            
            return self.execute_command(&sudo_cmd);
        } else {
            return Err(SshError::SudoPasswordRequired);
        }
    }
    
    #[allow(dead_code)]
    pub fn disconnect(&mut self) {
        self.session = None;
    }
    
    pub fn upload_file(&self, local_path: &str, remote_path: &str) -> Result<(), SshError> {
        let session = self.session.as_ref()
            .ok_or_else(|| SshError::ConnectionError("Not connected".to_string()))?;
            
        let local_path = Path::new(local_path);
        if !local_path.exists() {
            return Err(SshError::FileTransferError(format!("Local file not found: {}", local_path.display())));
        }
        
        let file_content = fs::read(local_path)
            .map_err(|e| SshError::IoError(e))?;
            
        let mut remote_file = session.scp_send(
            Path::new(remote_path),
            0o644,
            file_content.len() as u64,
            None
        ).map_err(|e| SshError::FileTransferError(e.to_string()))?;
        
        remote_file.write_all(&file_content)
            .map_err(|e| SshError::IoError(e))?;
            
        remote_file.send_eof()
            .map_err(|e| SshError::FileTransferError(e.to_string()))?;
            
        remote_file.wait_eof()
            .map_err(|e| SshError::FileTransferError(e.to_string()))?;
            
        remote_file.close()
            .map_err(|e| SshError::FileTransferError(e.to_string()))?;
            
        Ok(())
    }
    
    pub fn upload_directory(&self, local_dir: &str, remote_dir: &str) -> Result<(), SshError> {
        let local_path = Path::new(local_dir);
        if !local_path.exists() || !local_path.is_dir() {
            return Err(SshError::FileTransferError(format!("Local directory not found: {}", local_path.display())));
        }
        
        self.execute_command(&format!("mkdir -p {}", remote_dir))
            .map_err(|e| SshError::CommandError(format!("Failed to create remote directory: {}", e)))?;
            
        let entries = fs::read_dir(local_path)
            .map_err(|e| SshError::IoError(e))?;
            
        for entry in entries {
            let entry = entry.map_err(|e| SshError::IoError(e))?;
            let path = entry.path();
            let file_name = path.file_name().unwrap().to_string_lossy().to_string();
            let remote_path = format!("{}/{}", remote_dir, file_name);
            
            if path.is_dir() {
                let local_subdir = path.to_string_lossy().to_string();
                self.upload_directory(&local_subdir, &remote_path)?;
            } else {
                let local_file = path.to_string_lossy().to_string();
                self.upload_file(&local_file, &remote_path)?;
            }
        }
        
        Ok(())
    }
}
