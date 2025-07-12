# 高级TCP发包工具使用示例

## 安装依赖

```bash
pip install scapy
```

## 基本用法

### 1. 默认发包
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 -c 5
```

### 2. 从PCAP文件发包

#### 发送所有TCP数据包
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --pcap capture.pcap
```

#### 限制发送的数据包数量
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --pcap capture.pcap --max-packets 10
```

#### 自定义发包间隔
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --pcap capture.pcap -i 0.5
```

### 3. 自定义负载类型

#### HTTP GET请求
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --payload-type http_get --payload-config '{"host": "example.com", "path": "/api/test", "user_agent": "CustomBot/1.0"}'
```

#### HTTP POST请求
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --payload-type http_post --payload-config '{"host": "example.com", "path": "/api/data", "content": "{\"key\": \"value\"}", "content_type": "application/json"}'
```

#### JSON数据
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --payload-type json --payload-config '{"data": {"message": "Hello World", "timestamp": 1234567890, "user": "test"}}'
```

#### 原始数据
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --payload-type raw --payload-config '{"data": "Hello, this is raw data!"}'
```

#### 十六进制数据
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --payload-type hex --payload-config '{"data": "48656c6c6f20576f726c64"}'
```

### 4. 组合使用示例

#### 批量发送HTTP请求
```bash
python advanced_tcp_sender.py -t 192.168.1.100 -p 80 -c 10 -i 0.1 --payload-type http_get --payload-config '{"host": "192.168.1.100", "path": "/"}'
```

#### 从PCAP发送到不同目标
```bash
python advanced_tcp_sender.py -t 10.0.0.1 -p 443 --pcap web_traffic.pcap -i 0.5 --max-packets 20
```

## 负载类型说明

### 1. default
- 默认负载类型，包含原始头部和JSON数据
- 适用于特定的协议格式

### 2. http_get
- 构建HTTP GET请求
- 配置参数：
  - `host`: 目标主机
  - `path`: 请求路径
  - `user_agent`: 用户代理字符串

### 3. http_post
- 构建HTTP POST请求
- 配置参数：
  - `host`: 目标主机
  - `path`: 请求路径
  - `content`: POST内容
  - `content_type`: 内容类型
  - `user_agent`: 用户代理字符串

### 4. json
- 发送JSON格式数据
- 配置参数：
  - `data`: JSON对象

### 5. raw
- 发送原始数据
- 配置参数：
  - `data`: 字符串或字节数据

### 6. hex
- 从十六进制字符串构建数据
- 配置参数：
  - `data`: 十六进制字符串

## PCAP文件要求

- 支持标准PCAP格式文件
- 自动提取TCP数据包
- 显示数据包详细信息
- 支持限制发送数量

## 注意事项

1. 使用PCAP功能需要安装scapy库
2. 确保目标IP和端口正确
3. 自定义负载配置必须是有效的JSON格式
4. 发包间隔不要太短，避免对目标造成过大压力
5. 建议在测试环境中使用

## 错误处理

- 如果scapy未安装，会提示安装命令
- 如果PCAP文件不存在，会显示错误信息
- 如果负载配置JSON格式错误，会提示修正
- 连接失败会显示具体错误原因 