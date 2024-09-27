use std::env;
use std::fs::{self, OpenOptions, File};
use std::io::{Read, Write, BufWriter};
use std::process::Command;
use serde::Deserialize;
use ssh2::Session;
use std::net::TcpStream;
use std::path::Path;
use log::{info, error};
use chrono::Local;
use std::collections::HashMap;
use encoding_rs::GBK;
use encoding_rs_io::DecodeReaderBytesBuilder;

#[derive(Deserialize)]
struct Config {
    ssh_username: String,
    ssh_password: Option<String>,
    ssh_private_key_path: Option<String>,
    local_pre_upload_script: Option<String>,
    local_post_upload_script: Option<String>,
    remote_pre_upload_script: Option<String>,
    remote_post_upload_script: Option<String>,
    server_address: String,
    file_path: String,
    upload_path: String,
}

#[derive(Deserialize)]
struct ConfigFile {
    configs: HashMap<String, Config>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("用法: {} <命令> [配置名称]", args[0]);
        eprintln!("命令: run - 运行指定配置");
        eprintln!("      list - 列出所有可用配置");
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "list" => list_configs()?,
        "run" => {
            if args.len() != 3 {
                eprintln!("用法: {} run <配置名称>", args[0]);
                std::process::exit(1);
            }
            let config_name = &args[2];
            run_config(config_name)?;
        },
        _ => {
            eprintln!("未知命令: {}", command);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn list_configs() -> Result<(), Box<dyn std::error::Error>> {
    ensure_config_file_exists()?;

    let config_content = fs::read_to_string("config.toml")?;
    let config_file: ConfigFile = toml::from_str(&config_content)?;

    println!("可用的配置:");
    for (name, _) in config_file.configs.iter() {
        println!("- {}", name);
    }

    Ok(())
}

fn run_config(config_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Local::now();

    ensure_config_file_exists()?;

    let config_content = fs::read_to_string("config.toml")?;
    let config_file: ConfigFile = toml::from_str(&config_content)?;

    let config = config_file.configs.get(config_name).ok_or_else(|| {
        format!("错误：未找到名为 '{}' 的配置", config_name)
    })?;

    // 执行本地前置脚本
    if let Some(script) = &config.local_pre_upload_script {
        execute_local_script(script)?;
    }

    // 建立SSH连接
    let tcp = TcpStream::connect(&config.server_address)?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;

    // 根据提供的信息进行认证
    if let Some(password) = &config.ssh_password {
        sess.userauth_password(&config.ssh_username, password)?;
    } else if let Some(key_path) = &config.ssh_private_key_path {
        sess.userauth_pubkey_file(&config.ssh_username, None, Path::new(key_path), None)?;
    } else {
        return Err("错误：未提供密码或私钥路径".into());
    }

    // 执行远程前置脚本
    if let Some(script) = &config.remote_pre_upload_script {
        execute_remote_script(&sess, script)?;
    }

    // 上传文件
    let mut remote_file = sess.scp_send(Path::new(&config.upload_path), 0o644, 0, None)?;
    let local_content = fs::read(&config.file_path)?;
    remote_file.write_all(&local_content)?;
    remote_file.send_eof()?;
    remote_file.wait_eof()?;
    remote_file.close()?;
    remote_file.wait_close()?;

    info!("文件上传成功");

    // 执行远程后置脚本
    if let Some(script) = &config.remote_post_upload_script {
        execute_remote_script(&sess, script)?;
    }

    // 执行本地后置脚本
    if let Some(script) = &config.local_post_upload_script {
        execute_local_script(script)?;
    }

    log_operation(&start_time, &[config_name.to_string()], "成功", "文件上传成功")?;

    Ok(())
}

fn ensure_config_file_exists() -> Result<(), std::io::Error> {
    let txt = r#"#配置示例文件
[configs.default]
ssh_username = "user1"
ssh_password = "password1"
server_address = "example1.com:22"
file_path = "/path/to/local/file1"
upload_path = "/path/to/remote/file1"

[configs.production]
ssh_username = "user2"
ssh_private_key_path = "/home/user/.ssh/id_rsa"
server_address = "example2.com:22"
file_path = "/path/to/local/file2"
upload_path = "/path/to/remote/file2"
    "#;
    
    if !Path::new("config.toml").exists() {
        let mut file = File::create("config.toml")?;
        file.write_all(txt.as_bytes())?;
        println!("已创建示例配置文件 config.toml，请编辑后再次运行程序。");
        std::process::exit(0);
    }
    Ok(())
}

fn execute_local_script(script: &str) -> Result<(), std::io::Error> {
    let output = Command::new("cmd")
        .arg("/c")
        .arg(script)
        .output()?;

    let stdout = decode_gbk(&output.stdout);
    let stderr = decode_gbk(&output.stderr);

    if !output.status.success() {
        let error_msg = format!("本地脚本执行失败:\n标准输出: {}\n错误输出: {}", stdout, stderr);
        error!("{}", error_msg);
        println!("{}", error_msg);
        log_script_output("本地脚本", &error_msg)?;
        Err(std::io::Error::new(std::io::ErrorKind::Other, error_msg))
    } else {
        let success_msg = format!("本地脚本执行成功:\n标准输出: {}\n错误输出: {}", stdout, stderr);
        info!("{}", success_msg);
        println!("{}", success_msg);
        log_script_output("本地脚本", &success_msg)?;
        Ok(())
    }
}

fn decode_gbk(input: &[u8]) -> String {
    let mut reader = DecodeReaderBytesBuilder::new()
        .encoding(Some(GBK))
        .build(input);
    let mut decoded = String::new();
    reader.read_to_string(&mut decoded).unwrap_or_default();
    decoded
}

fn execute_remote_script(sess: &Session, script: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = sess.channel_session()?;
    channel.exec(script)?;
    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;
    let exit_status = channel.exit_status()?;

    if exit_status != 0 {
        let error_msg = format!("远程脚本执行失败 (状态码 {}):\n{}", exit_status, output);
        error!("{}", error_msg);
        println!("{}", error_msg);
        log_script_output("远程脚本", &error_msg)?;
        Err(error_msg.into())
    } else {
        let success_msg = format!("远程脚本执行成功:\n{}", output);
        info!("{}", success_msg);
        println!("{}", success_msg);
        log_script_output("远程脚本", &success_msg)?;
        Ok(())
    }
}

fn log_script_output(script_type: &str, output: &str) -> Result<(), std::io::Error> {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] {} 输出:\n{}\n", timestamp, script_type, output);

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("script_output.log")?;
    
    let mut writer = BufWriter::new(file);
    writer.write_all(log_entry.as_bytes())?;
    writer.flush()?;

    Ok(())
}

fn log_operation(start_time: &chrono::DateTime<Local>, args: &[String], status: &str, message: &str) -> Result<(), std::io::Error> {
    let end_time = Local::now();
    let duration = end_time.signed_duration_since(*start_time);
    
    let log_entry = format!(
        "[{}] 执行时间: {}, 持续时间: {}ms, 命令参数: {:?}, 状态: {}, 消息: {}\n",
        end_time.format("%Y-%m-%d %H:%M:%S"),
        start_time.format("%Y-%m-%d %H:%M:%S"),
        duration.num_milliseconds(),
        args,
        status,
        message
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("operation_log.txt")?;

    file.write_all(log_entry.as_bytes())?;

    Ok(())
}


mod test {
    use crate::execute_local_script;

    pub fn test() {
        execute_local_script("dir");
    }

    pub fn test2() {
        execute_local_script("D:/0-work/0-zqcm/atb/test.cmd");
}
}
