# 高级TCP发包工具

一个功能强大的TCP数据包发送工具，支持多种发包方式和自定义负载。

## 功能特性

### 🔥 核心功能
- **批量发包**: 支持指定数量的数据包发送
- **自定义间隔**: 可调节发包间隔时间
- **详细日志**: 实时显示发包状态和统计信息
- **连接管理**: 自动处理连接建立和关闭

### 📦 PCAP文件支持
- **自动解析**: 从PCAP文件提取TCP数据包
- **数据包信息**: 显示源地址、目标地址、负载大小等
- **灵活控制**: 支持限制发送的数据包数量
- **批量重放**: 将捕获的流量重新发送到指定目标

### 🎯 自定义负载
- **多种格式**: 支持HTTP、JSON、原始数据、十六进制等
- **模板系统**: 预定义常用负载模板
- **灵活配置**: 通过JSON配置自定义负载内容
- **实时构建**: 动态生成数据包内容

## 安装依赖

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install scapy>=2.4.5
```

## 快速开始

### 基本用法

```bash
# 发送单个数据包
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080

# 批量发送
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 -c 10 -i 0.5
```

### PCAP文件发包

```bash
# 从PCAP文件发送所有TCP数据包
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --pcap capture.pcap

# 限制发送数量
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --pcap capture.pcap --max-packets 5
```

### 自定义负载

```bash
# HTTP GET请求
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --payload-type http_get --payload-config '{"host": "example.com", "path": "/api/test"}'

# JSON数据
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --payload-type json --payload-config '{"data": {"message": "Hello World"}}'
```

## 命令行参数

### 基本参数
- `-t, --target`: 目标IP地址 (默认: 1.2.3.4)
- `-p, --port`: 目标端口 (默认: 9004)
- `-c, --count`: 发包数量 (默认: 1)
- `-i, --interval`: 发包间隔秒数 (默认: 1.0)
- `--timeout`: 连接超时时间 (默认: 5秒)

### PCAP参数
- `--pcap`: 从PCAP文件发送数据包
- `--max-packets`: 限制发送的PCAP数据包数量

### 自定义负载参数
- `--payload-type`: 负载类型 (default/http_get/http_post/json/raw/hex)
- `--payload-config`: 负载配置JSON字符串

### 自定义数据参数
- `--version`: 自定义版本号
- `--os`: 自定义操作系统
- `--arch`: 自定义架构
- `--key`: 自定义权限密钥

## 负载类型详解

### 1. default
默认负载类型，包含原始头部和JSON数据。

### 2. http_get
构建HTTP GET请求：
```json
{
  "host": "example.com",
  "path": "/api/test",
  "user_agent": "CustomBot/1.0"
}
```

### 3. http_post
构建HTTP POST请求：
```json
{
  "host": "example.com",
  "path": "/api/data",
  "content": "{\"key\": \"value\"}",
  "content_type": "application/json"
}
```

### 4. json
发送JSON格式数据：
```json
{
  "data": {
    "message": "Hello World",
    "timestamp": 1234567890
  }
}
```

### 5. raw
发送原始数据：
```json
{
  "data": "Hello, this is raw data!"
}
```

### 6. hex
从十六进制字符串构建数据：
```json
{
  "data": "48656c6c6f20576f726c64"
}
```

## 使用示例

### 测试环境搭建

1. 创建测试PCAP文件：
```bash
python test_pcap_creator.py
```

2. 使用测试PCAP文件：
```bash
python advanced_tcp_sender.py -t 127.0.0.1 -p 8080 --pcap test_packets.pcap
```

### 实际应用场景

#### 1. 网络测试
```bash
# 测试Web服务器响应
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 -c 100 -i 0.1 --payload-type http_get --payload-config '{"host": "192.168.1.100", "path": "/"}'
```

#### 2. 流量重放
```bash
# 重放捕获的流量
python advanced_tcp_sender.py -t 10.0.0.1 -p 443 --pcap captured_traffic.pcap -i 0.5
```

#### 3. API测试
```bash
# 测试API接口
python advanced_tcp_sender.py -t api.example.com -p 443 --payload-type http_post --payload-config '{"host": "api.example.com", "path": "/users", "content": "{\"name\": \"test\"}", "content_type": "application/json"}'
```

## 文件结构

```
TCP发包工具/
├── advanced_tcp_sender.py    # 主程序
├── test_pcap_creator.py      # PCAP测试文件创建工具
├── usage_examples.md         # 详细使用示例
├── requirements.txt          # 依赖管理
└── README.md                # 项目说明
```

## 注意事项

1. **权限要求**: 某些功能可能需要管理员权限
2. **网络环境**: 确保目标网络可达
3. **安全考虑**: 仅在授权的测试环境中使用
4. **性能影响**: 避免过高的发包频率
5. **依赖管理**: 确保scapy库正确安装

## 错误处理

- 自动检测scapy库安装状态
- 详细的错误信息和解决建议
- 连接失败时的重试机制
- 数据包格式验证

## 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 许可证

本项目仅供学习和研究使用，请遵守相关法律法规。 
