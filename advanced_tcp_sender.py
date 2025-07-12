#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级TCP发包工具
支持批量发包、自定义参数、详细日志、pcap文件解析和自定义发包内容
"""

import socket
import json
import time
import struct
import argparse
import threading
import os
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any

try:
    from scapy.all import rdpcap, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[警告] 未安装scapy库，pcap功能将不可用。请运行: pip install scapy")

class PCAPParser:
    """PCAP文件解析器"""
    
    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy库未安装，无法解析pcap文件")
    
    def parse_pcap(self, pcap_file: str) -> List[Dict[str, Any]]:
        """解析pcap文件，提取TCP数据包"""
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"pcap文件不存在: {pcap_file}")
        
        print(f"[*] 正在解析pcap文件: {pcap_file}")
        packets = rdpcap(pcap_file)
        
        tcp_packets = []
        for i, packet in enumerate(packets):
            if IP in packet and TCP in packet:
                # 提取IP和TCP层信息
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                
                # 提取负载数据
                payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
                
                packet_info = {
                    'index': i + 1,
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'payload': payload,
                    'payload_hex': payload.hex(),
                    'payload_size': len(payload),
                    'flags': tcp_layer.flags,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                }
                
                tcp_packets.append(packet_info)
        
        print(f"[+] 解析完成，共找到 {len(tcp_packets)} 个TCP数据包")
        return tcp_packets
    
    def display_packets(self, packets: List[Dict[str, Any]], max_display: int = 5):
        """显示解析的数据包信息"""
        print(f"\n[*] 前{min(max_display, len(packets))}个数据包信息:")
        print("-" * 80)
        
        for i, packet in enumerate(packets[:max_display]):
            print(f"数据包 {packet['index']}:")
            print(f"  源地址: {packet['src_ip']}:{packet['src_port']}")
            print(f"  目标地址: {packet['dst_ip']}:{packet['dst_port']}")
            print(f"  负载大小: {packet['payload_size']} 字节")
            print(f"  负载内容: {packet['payload'][:50]}{'...' if len(packet['payload']) > 50 else ''}")
            print(f"  十六进制: {packet['payload_hex'][:100]}{'...' if len(packet['payload_hex']) > 100 else ''}")
            print("-" * 80)

class CustomPayloadBuilder:
    """自定义负载构建器"""
    
    def __init__(self):
        self.templates = {
            'http_get': self._build_http_get,
            'http_post': self._build_http_post,
            'json': self._build_json,
            'raw': self._build_raw,
            'hex': self._build_hex
        }
    
    def _build_http_get(self, **kwargs) -> bytes:
        """构建HTTP GET请求"""
        host = kwargs.get('host', 'localhost')
        path = kwargs.get('path', '/')
        user_agent = kwargs.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        request = f"GET {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        
        return request.encode('utf-8')
    
    def _build_http_post(self, **kwargs) -> bytes:
        """构建HTTP POST请求"""
        host = kwargs.get('host', 'localhost')
        path = kwargs.get('path', '/')
        content = kwargs.get('content', '')
        content_type = kwargs.get('content_type', 'application/json')
        user_agent = kwargs.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += f"Content-Type: {content_type}\r\n"
        request += f"Content-Length: {len(content)}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += content
        
        return request.encode('utf-8')
    
    def _build_json(self, **kwargs) -> bytes:
        """构建JSON数据"""
        data = kwargs.get('data', {})
        return json.dumps(data, separators=(',', ':')).encode('utf-8')
    
    def _build_raw(self, **kwargs) -> bytes:
        """构建原始数据"""
        data = kwargs.get('data', '')
        if isinstance(data, str):
            return data.encode('utf-8')
        return data
    
    def _build_hex(self, **kwargs) -> bytes:
        """从十六进制字符串构建数据"""
        hex_data = kwargs.get('data', '')
        return bytes.fromhex(hex_data)
    
    def build_payload(self, template: str, **kwargs) -> bytes:
        """根据模板构建负载"""
        if template not in self.templates:
            raise ValueError(f"不支持的模板类型: {template}")
        
        return self.templates[template](**kwargs)

class TCPSender:
    def __init__(self, target_ip, target_port, timeout=5):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.success_count = 0
        self.fail_count = 0
        self.lock = threading.Lock()
        self.payload_builder = CustomPayloadBuilder()
    
    def create_payload(self, custom_data=None, payload_type='default', payload_config=None):
        """创建数据包内容"""
        if payload_type == 'default':
            # 原始数据包头部
            raw_data = b'........................o........'
            
            # 默认JSON数据
            default_data = {
                "version": "0.38.0",
                "hostname": "",
                "os": "windows", 
                "arch": "amd64",
                "user": "",
                "privilege_key": "2640fe6fea802876d956d46626b9d30e",
                "timestamp": int(time.time()),
                "run_id": "",
                "metas": None,
                "pool_count": 1
            }
            
            # 如果提供了自定义数据，则合并
            if custom_data:
                default_data.update(custom_data)
            
            # 将JSON转换为字节
            json_bytes = json.dumps(default_data, separators=(',', ':')).encode('utf-8')
            
            # 组合完整数据包
            full_payload = raw_data + json_bytes
            
            return full_payload
        else:
            # 使用自定义负载构建器
            if payload_config is None:
                payload_config = {}
            
            return self.payload_builder.build_payload(payload_type, **payload_config)
    
    def send_single_packet(self, payload, packet_id=1):
        """发送单个TCP数据包"""
        start_time = time.time()
        
        try:
            # 创建TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            print(f"[{packet_id:03d}] 正在连接到 {self.target_ip}:{self.target_port}...")
            
            # 连接到目标
            sock.connect((self.target_ip, self.target_port))
            print(f"[{packet_id:03d}] [+] 连接成功!")
            
            # 发送数据
            print(f"[{packet_id:03d}] [+] 发送数据包，长度: {len(payload)} 字节")
            sock.send(payload)
            print(f"[{packet_id:03d}] [+] 数据包发送完成")
            
            # 尝试接收响应
            response = None
            try:
                response = sock.recv(1024)
                if response:
                    print(f"[{packet_id:03d}] [+] 收到响应: {response}")
                else:
                    print(f"[{packet_id:03d}] [+] 未收到响应")
            except socket.timeout:
                print(f"[{packet_id:03d}] [+] 等待响应超时")
            except Exception as e:
                print(f"[{packet_id:03d}] [+] 接收响应时出错: {e}")
            
            # 记录成功
            with self.lock:
                self.success_count += 1
            
            elapsed_time = time.time() - start_time
            print(f"[{packet_id:03d}] [+] 发包成功，耗时: {elapsed_time:.3f}秒")
            
            return True, response
            
        except socket.timeout:
            print(f"[{packet_id:03d}] [-] 连接超时")
        except ConnectionRefusedError:
            print(f"[{packet_id:03d}] [-] 连接被拒绝，目标端口可能未开放")
        except Exception as e:
            print(f"[{packet_id:03d}] [-] 发送失败: {e}")
        finally:
            sock.close()
        
        # 记录失败
        with self.lock:
            self.fail_count += 1
        
        return False, None
    
    def send_batch_packets(self, count=1, interval=1.0, custom_data=None, payload_type='default', payload_config=None):
        """批量发送数据包"""
        print("=" * 60)
        print("批量TCP发包工具")
        print("=" * 60)
        print(f"目标: {self.target_ip}:{self.target_port}")
        print(f"发包数量: {count}")
        print(f"发包间隔: {interval}秒")
        print(f"负载类型: {payload_type}")
        print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # 创建数据包
        payload = self.create_payload(custom_data, payload_type, payload_config)
        
        # 显示数据包内容
        print("[*] 数据包内容:")
        if payload_type == 'default':
            print(f"原始数据: {payload[:33]}")
            print(f"JSON数据: {payload[33:].decode('utf-8')}")
        else:
            print(f"负载内容: {payload[:100]}{'...' if len(payload) > 100 else ''}")
            print(f"十六进制: {payload.hex()[:200]}{'...' if len(payload.hex()) > 200 else ''}")
        print("=" * 60)
        
        start_time = time.time()
        
        for i in range(1, count + 1):
            success, response = self.send_single_packet(payload, i)
            
            # 如果不是最后一个包，则等待指定间隔
            if i < count:
                time.sleep(interval)
        
        total_time = time.time() - start_time
        
        # 输出统计信息
        print("=" * 60)
        print("发包统计:")
        print(f"总发包数: {count}")
        print(f"成功数量: {self.success_count}")
        print(f"失败数量: {self.fail_count}")
        print(f"成功率: {(self.success_count/count)*100:.2f}%")
        print(f"总耗时: {total_time:.3f}秒")
        print(f"平均发包时间: {total_time/count:.3f}秒")
        print(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
    
    def send_pcap_packets(self, pcap_file: str, interval: float = 1.0, max_packets: Optional[int] = None):
        """从pcap文件发送数据包"""
        try:
            parser = PCAPParser()
            packets = parser.parse_pcap(pcap_file)
            
            if max_packets:
                packets = packets[:max_packets]
            
            # 显示数据包信息
            parser.display_packets(packets)
            
            print(f"\n[*] 开始发送 {len(packets)} 个数据包...")
            print("=" * 60)
            
            start_time = time.time()
            
            for i, packet in enumerate(packets):
                print(f"\n[数据包 {i+1}/{len(packets)}] 发送来自pcap的数据包")
                print(f"源地址: {packet['src_ip']}:{packet['src_port']}")
                print(f"目标地址: {packet['dst_ip']}:{packet['dst_port']}")
                print(f"负载大小: {packet['payload_size']} 字节")
                
                success, response = self.send_single_packet(packet['payload'], i+1)
                
                if i < len(packets) - 1:
                    time.sleep(interval)
            
            total_time = time.time() - start_time
            
            # 输出统计信息
            print("=" * 60)
            print("PCAP发包统计:")
            print(f"总发包数: {len(packets)}")
            print(f"成功数量: {self.success_count}")
            print(f"失败数量: {self.fail_count}")
            print(f"成功率: {(self.success_count/len(packets))*100:.2f}%")
            print(f"总耗时: {total_time:.3f}秒")
            print(f"平均发包时间: {total_time/len(packets):.3f}秒")
            print("=" * 60)
            
        except Exception as e:
            print(f"[-] 处理pcap文件时出错: {e}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='高级TCP发包工具')
    parser.add_argument('-t', '--target', default='1.2.3.4', help='目标IP地址 (默认: 1.2.3.4)')
    parser.add_argument('-p', '--port', type=int, default=9004, help='目标端口 (默认: 9004)')
    parser.add_argument('-c', '--count', type=int, default=1, help='发包数量 (默认: 1)')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='发包间隔秒数 (默认: 1.0)')
    parser.add_argument('--timeout', type=int, default=5, help='连接超时时间 (默认: 5秒)')
    
    # 自定义数据参数
    parser.add_argument('--version', default='0.38.0', help='自定义版本号')
    parser.add_argument('--os', default='windows', help='自定义操作系统')
    parser.add_argument('--arch', default='amd64', help='自定义架构')
    parser.add_argument('--key', default='2640fe6fea802876d956d46626b9d30e', help='自定义权限密钥')
    
    # PCAP文件参数
    parser.add_argument('--pcap', help='从pcap文件发送数据包')
    parser.add_argument('--max-packets', type=int, help='限制发送的pcap数据包数量')
    
    # 自定义负载参数
    parser.add_argument('--payload-type', choices=['default', 'http_get', 'http_post', 'json', 'raw', 'hex'], 
                       default='default', help='负载类型 (默认: default)')
    parser.add_argument('--payload-config', help='负载配置JSON字符串')
    
    args = parser.parse_args()
    
    # 创建发送器实例
    sender = TCPSender(args.target, args.port, args.timeout)
    
    # 处理pcap文件
    if args.pcap:
        if not SCAPY_AVAILABLE:
            print("[-] 错误: 需要安装scapy库来支持pcap功能")
            print("请运行: pip install scapy")
            sys.exit(1)
        
        sender.send_pcap_packets(args.pcap, args.interval, args.max_packets)
        return
    
    # 处理自定义负载
    payload_config = None
    if args.payload_config:
        try:
            payload_config = json.loads(args.payload_config)
        except json.JSONDecodeError:
            print("[-] 错误: payload-config必须是有效的JSON格式")
            sys.exit(1)
    
    # 创建自定义数据
    custom_data = {
        "version": args.version,
        "os": args.os,
        "arch": args.arch,
        "privilege_key": args.key
    }
    
    # 开始发包
    sender.send_batch_packets(args.count, args.interval, custom_data, args.payload_type, payload_config)

if __name__ == "__main__":
    main() 
