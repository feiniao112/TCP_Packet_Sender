#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
创建测试用的PCAP文件
用于测试TCP发包工具的pcap功能
"""

try:
    from scapy.all import *
    print("[+] scapy库已安装，可以创建pcap文件")
except ImportError:
    print("[-] 错误: 需要安装scapy库")
    print("请运行: pip install scapy")
    exit(1)

def create_test_pcap():
    """创建测试用的pcap文件"""
    
    # 创建一些测试数据包
    packets = []
    
    # 1. HTTP GET请求
    http_get_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot/1.0\r\nConnection: close\r\n\r\n"
    pkt1 = IP(dst="192.168.1.100")/TCP(sport=12345, dport=80)/Raw(load=http_get_payload)
    packets.append(pkt1)
    
    # 2. HTTP POST请求
    http_post_payload = b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"message\": \"Hello World\"}"
    pkt2 = IP(dst="192.168.1.100")/TCP(sport=12346, dport=80)/Raw(load=http_post_payload)
    packets.append(pkt2)
    
    # 3. JSON数据
    json_payload = b'{"version": "1.0", "action": "test", "data": {"id": 123, "name": "test"}}'
    pkt3 = IP(dst="192.168.1.100")/TCP(sport=12347, dport=8080)/Raw(load=json_payload)
    packets.append(pkt3)
    
    # 4. 原始数据
    raw_payload = b"Hello, this is a test message from pcap!"
    pkt4 = IP(dst="192.168.1.100")/TCP(sport=12348, dport=9000)/Raw(load=raw_payload)
    packets.append(pkt4)
    
    # 5. 十六进制数据
    hex_payload = bytes.fromhex("48656c6c6f20576f726c64")  # "Hello World"
    pkt5 = IP(dst="192.168.1.100")/TCP(sport=12349, dport=9001)/Raw(load=hex_payload)
    packets.append(pkt5)
    
    # 保存到pcap文件
    filename = "test_packets.pcap"
    wrpcap(filename, packets)
    
    print(f"[+] 已创建测试pcap文件: {filename}")
    print(f"[+] 包含 {len(packets)} 个TCP数据包")
    
    # 显示数据包信息
    print("\n[*] 数据包详情:")
    for i, pkt in enumerate(packets, 1):
        if IP in pkt and TCP in pkt:
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
            
            print(f"数据包 {i}:")
            print(f"  源地址: {ip_layer.src}:{tcp_layer.sport}")
            print(f"  目标地址: {ip_layer.dst}:{tcp_layer.dport}")
            print(f"  负载大小: {len(payload)} 字节")
            print(f"  负载内容: {payload[:50]}{'...' if len(payload) > 50 else ''}")
            print("-" * 60)
    
    return filename

def test_pcap_parsing():
    """测试pcap解析功能"""
    try:
        from advanced_tcp_sender import PCAPParser
        
        filename = create_test_pcap()
        parser = PCAPParser()
        packets = parser.parse_pcap(filename)
        
        print(f"\n[+] PCAP解析测试成功!")
        print(f"[+] 解析到 {len(packets)} 个TCP数据包")
        
        # 显示前3个数据包
        parser.display_packets(packets, 3)
        
    except Exception as e:
        print(f"[-] PCAP解析测试失败: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("PCAP测试文件创建工具")
    print("=" * 60)
    
    # 创建测试pcap文件
    filename = create_test_pcap()
    
    print(f"\n[*] 使用方法:")
    print(f"python advanced_tcp_sender.py -t 192.168.1.100 -p 80 --pcap {filename}")
    print(f"python advanced_tcp_sender.py -t 192.168.1.100 -p 8080 --pcap {filename} --max-packets 3")
    
    # 测试解析功能
    print(f"\n[*] 测试PCAP解析功能...")
    test_pcap_parsing()
    
    print("\n[+] 测试完成!") 