# 文件上传工具

这是一个用Rust编写的命令行工具,用于通过SSH将文件上传到远程服务器。

## 功能

- 支持多个配置文件
- 使用SSH进行安全文件传输
- 支持密码和私钥认证
- 可执行本地和远程脚本(上传前和上传后)
- 日志记录操作和脚本输出

## 使用方法

1. 首次运行程序时,会创建一个示例配置文件`config.toml`。请根据您的需求编辑此文件。

2. 列出所有可用配置:

   ```
   cargo run -- list
   ```

3. 使用指定配置上传文件:

   ```
   cargo run -- run <配置名称>
   ```

## 配置文件

配置文件(`config.toml`)的结构如下:
```toml
toml
[configs.<配置名称>]
ssh_username = "用户名"
ssh_password = "密码" # 或使用 ssh_private_key_path
ssh_private_key_path = "/path/to/private/key"
server_address = "服务器地址:端口"
file_path = "/本地文件路径"
upload_path = "/远程文件路径"
local_pre_upload_script = "本地前置脚本" # 可选
local_post_upload_script = "本地后置脚本" # 可选
remote_pre_upload_script = "远程前置脚本" # 可选
remote_post_upload_script = "远程后置脚本" # 可选
```

## 日志

- 操作日志保存在`operation_log.txt`文件中
- 脚本输出日志保存在`script_output.log`文件中

## 依赖

- ssh2
- serde
- toml
- log
- env_logger
- chrono
- encoding_rs
- encoding_rs_io

## 注意事项

- 请确保您有权限访问目标服务器和文件
- 使用私钥认证时,请确保私钥文件的权限设置正确
- 在Windows环境下运行时,本地脚本将使用cmd执行