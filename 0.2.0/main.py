import socket
import struct
import threading
import argparse
import time
import sys
import os
import json
import random
import subprocess
import platform
import select  # 添加select模块导入
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm  # 添加tqdm导入
try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP, ARP, Ether, srp, RandShort, send
    from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy库未安装，高级扫描功能将受限")
    print("[!] 安装命令: pip install scapy")

class AdvancedScanner:
    def __init__(self, target, options):
        self.target = target
        self.options = options
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.hosts_up = []
        self.os_info = {}
        self.service_versions = {}
        self.scan_results = {}
        self.progress_bar = None  # 添加进度条属性
        self.thread_lock = threading.Lock()  # 添加线程锁
        
        # 常见服务映射
        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
            137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
            161: "SNMP", 162: "SNMP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 514: "Syslog", 993: "IMAPS", 995: "POP3S",
            1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        
        # 服务指纹库
        self.service_fingerprints = {
            "SSH": [b"SSH-", b"OpenSSH", b"libssh"],
            "HTTP": [b"HTTP/", b"Server:", b"<!DOCTYPE", b"<html>"],
            "FTP": [b"220 ", b"FTP", b"FileZilla", b"vsFTPd", b"ProFTPD"],
            "SMTP": [b"220 ", b"ESMTP", b"Postfix", b"Sendmail", b"SMTP"],
            "MySQL": [b"\x00\x00\x00\x0a", b"mysql_native_password", b"MariaDB"],
            "RDP": [b"\x03\x00\x00", b"MS-RDPBCGR"],
            "Telnet": [b"Telnet", b"\xff\xfb"],
            "POP3": [b"+OK", b"POP3"],
            "IMAP": [b"* OK ", b"IMAP"],
        }
        
        # 操作系统指纹库 (TTL值和窗口大小特征)
        self.os_fingerprints = {
            # TTL和窗口大小的组合来识别OS
            (64, 5840): "Linux",
            (64, 14600): "Linux (kernel 3.x)",
            (64, 65535): "Linux/Unix-like",
            (128, 8192): "Windows 10/11/Server",
            (128, 65535): "Windows 7/8/Server",
            (128, 16384): "Windows",
            (255, 4128): "Cisco IOS",
            (255, 8760): "Solaris/AIX",
            (64, 16384): "macOS/iOS",
        }
        
        # 常见漏洞库 (简易版)
        self.vulnerability_checks = {
            "HTTP": self.http_vulnerability_check,
            "SSH": self.ssh_vulnerability_check,
            "FTP": self.ftp_vulnerability_check,
            "SMB": self.smb_vulnerability_check,
        }
        
        # 添加 nmap 风格的扫描策略
        self.port_scan_strategy = {
            'quick': [20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
            'common': [f for f in range(1, 1024)],  # 常用端口
            'full': [f for f in range(1, 65536)]    # 全端口扫描
        }
        
        # 扫描控制参数
        self.max_retries = 2
        self.min_timeout = 0.5
        self.max_timeout = 3.0
        self.adaptive_timing = True  # 自适应时序
        self.timing_stats = {'success': 0, 'timeout': 0}  # 扫描统计
        
        # 每批次的端口数量(根据timing参数调整)
        self.batch_size = {
            1: 10,   # 极慢
            2: 30,   # 慢
            3: 100,  # 正常
            4: 300,  # 快
            5: 500   # 极快
        }[options.timing]
        
        # 添加Web应用指纹库
        self.web_fingerprints = {
            'wordpress': ['/wp-login.php', '/wp-admin', '/wp-content'],
            'joomla': ['/administrator', '/components', '/templates'],
            'drupal': ['/user/login', '/admin', '/sites/default'],
            'phpmyadmin': ['/phpmyadmin', '/pma', '/myadmin'],
            'tomcat': ['/manager/html', '/host-manager/html'],
            'weblogic': ['/console', '/em', '/console/login/LoginForm.jsp'],
            'jenkins': ['/jenkins', '/login'],
            'spring': ['/actuator', '/swagger-ui.html', '/env'],
        }
        
        # 添加WAF特征库
        self.waf_signatures = {
            'cloudflare': ['cloudflare-nginx', '__cfduid', 'cf-ray'],
            'f5_bigip': ['BigIP', 'F5', 'TS'],
            'imperva': ['incapsula', '_incap_', 'visid_incap'],
            'akamai': ['akamai', 'aka-', 'x-akamai-'],
            'aws_waf': ['awselb', 'X-AMZ-CF-ID'],
        }
        
        # SMB协议版本特征库
        self.smb_versions = {
            b"\xffSMB": "SMBv1",
            b"\xfeSMB": "SMBv2/3",
            b"\xfdSMB": "SMBv3",
        }

        # # SMB已知漏洞特征
        # self.smb_vulnerabilities = {
        #     "MS17-010": {"name": "永恒之蓝(EternalBlue)", "check": self.check_ms17_010},
        #     "MS08-067": {"name": "远程代码执行漏洞", "check": self.check_ms08_067},
        #     "CVE-2020-0796": {"name": "SMBGhost", "check": self.check_cve_2020_0796},
        # }

        # DNS协议特征
        self.dns_vulnerable_zones = ["AXFR", "IXFR"]

        # MySQL协议指纹
        self.mysql_protocol = {
            "greeting": b"\x0a",  # 协议版本10
            "error": b"\xff",     # 错误包标识
        }

        # PostgreSQL协议指纹
        self.pgsql_protocol = {
            "startup": b"\x00\x03\x00\x00",
        }

        # MSSQL协议指纹
        self.mssql_protocol = {
            "response": b"\x04\x01",
        }

        # 添加服务版本检测数据库
        self.service_probes = {
            "SSH": {"probe": b"", "banners": True},
            "HTTP": {"probe": b"GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n", "banners": True},
            "FTP": {"probe": b"", "banners": True},
            "SMTP": {"probe": b"", "banners": True},
            "POP3": {"probe": b"", "banners": True},
            "IMAP": {"probe": b"", "banners": True},
            "MySQL": {"probe": b"\x0a\x00\x00\x00\x0a", "banners": False},
            "MSSQL": {"probe": b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00", "banners": False},
            "SMB": {"probe": b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00", "banners": False},
            "RDP": {"probe": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00", "banners": False},
            "Redis": {"probe": b"*1\r\n$4\r\nPING\r\n", "banners": False},
            "MongoDB": {"probe": b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00", "banners": False},
        }

        # 添加SSL/TLS支持
        self.ssl_enabled = hasattr(options, 'ssl') and options.ssl
        self.ssl_versions = {
            "SSLv2": 0x0002,
            "SSLv3": 0x0300,
            "TLSv1.0": 0x0301,
            "TLSv1.1": 0x0302,
            "TLSv1.2": 0x0303,
            "TLSv1.3": 0x0304
        }

        # 随机User-Agent列表
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (Linux; Android 10; SM-A205U)'
        ]
        
        # 扫描控制参数增强
        self.use_proxy = options.proxy if hasattr(options, 'proxy') else None
        self.stealth_mode = options.stealth if hasattr(options, 'stealth') else False
        self.waf_evasion = options.waf_evasion if hasattr(options, 'waf_evasion') else False

        # 打印横幅
        self._print_banner()
        print(f"\n[*] 目标地址: {self.target}")
        if '/' in self.target:
            print(f"[*] 网络范围: {self.target}")
        else:
            try:
                ip = socket.gethostbyname(self.target)
                if ip != self.target:
                    print(f"[*] 解析地址: {ip}")
            except:
                pass
    
    def _print_banner(self):
        """打印扫描工具的横幅"""
        banner = """
██████╗ ██████╗ ██╗  ██╗    ███████╗ ██████╗ █████╗ ██╗   ██╗
██╔══██╗██╔══██╗╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗██║   ██║
██║  ██╗██████╔╝ ╚███╔╝     ███████╗██║     ██████╔╝██║   ██║
██║  ██╗██╔══██╗ ██╔██╗     ╚════██║██║     ██╔══██╗██║   ██║
██████╔╝██║  ██║██╔╝ ██╗    ███████║╚██████╗██║  ██║╚██████╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝
                                                  作者:BushSEC
        """
        print(banner)
        print("\n端口扫描工具")
        print("=" * 50)
    
    def resolve_hostname(self):
        """将主机名解析为IP地址"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"无法解析主机名: {self.target}")
            sys.exit(1)
    
    def get_interface_ip(self):
        """获取本地主接口IP地址"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # 不需要真正连接
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    
    def network_discovery(self):
        """改进的网络发现 - 查找活跃主机"""
        target_ip = self.resolve_hostname()
        
        # 单个主机直接返回
        if '/' not in self.target:
            self.hosts_up.append(target_ip)
            return [target_ip]
        
        # 对于CIDR网段，执行网络发现
        network = self.target
        print(f"[*] 开始网络发现: {network}")
        
        if self.options.discovery_method == 'ping':
            return self.ping_sweep(network)
        elif self.options.discovery_method == 'arp' and '/24' in network:
            return self.arp_scan(network)
        else:
            return self.ping_sweep(network)
    
    def ping_sweep(self, network):
        """改进的ICMP Ping扫描"""
        if '/' not in network:  # 单个IP
            if self.ping_host(network):
                print(f"[+] 主机在线: {network}")
                return [network]
            return []
            
        alive_hosts = []
        try:
            print(f"[*] 执行ICMP Ping扫描: {network}")
            from ipaddress import IPv4Network
            
            network_obj = IPv4Network(network, strict=False)
            total_hosts = network_obj.num_addresses
            
            if total_hosts > 256 and not self.options.force:
                print(f"[!] 网络过大 ({total_hosts} 个主机)，如需继续请使用 --force 参数")
                return [self.resolve_hostname()]
                
            with ThreadPoolExecutor(max_workers=min(100, total_hosts)) as executor:
                futures = []
                for ip in network_obj.hosts():
                    ip_str = str(ip)
                    futures.append(executor.submit(self.ping_host, ip_str))
                
                for i, future in enumerate(futures):
                    if future.result():
                        host = str(list(network_obj.hosts())[i])
                        alive_hosts.append(host)
                        print(f"[+] 主机在线: {host}")
            
            # 如果没有发现活跃主机，至少返回目标IP
            if not alive_hosts and '/' not in self.target:
                alive_hosts.append(self.resolve_hostname())
                
            print(f"[*] 发现 {len(alive_hosts)} 个活跃主机")
            return alive_hosts
            
        except Exception as e:
            print(f"[!] Ping扫描出错: {e}")
            return [self.resolve_hostname()]
    
    def ping_host(self, ip):
        """对单个主机执行ping"""
        if SCAPY_AVAILABLE:
            try:
                # 使用Scapy进行ICMP ping
                packet = IP(dst=ip)/ICMP()
                reply = sr1(packet, timeout=1, verbose=0)
                if reply is not None:
                    return True
            except:
                pass
        
        # 回退到系统ping命令
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    
    def arp_scan(self, network):
        """ARP扫描本地网络"""
        if not SCAPY_AVAILABLE:
            return [self.resolve_hostname()]
        
        try:
            print(f"[*] 执行ARP扫描: {network}")
            alive_hosts = []
            
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), 
                          timeout=2, verbose=0)
            
            for _, rcv in ans:
                ip = rcv.sprintf(r"%ARP.psrc%")
                mac = rcv.sprintf(r"%Ether.src%")
                alive_hosts.append(ip)
                print(f"[+] 主机在线: {ip} ({mac})")
            
            print(f"[*] 发现 {len(alive_hosts)} 个活跃主机")
            return alive_hosts
            
        except Exception as e:
            print(f"[!] ARP扫描出错: {e}")
            return [self.resolve_hostname()]
    
    def update_progress(self, advance=1):
        """更新进度条"""
        if self.progress_bar is not None:
            self.progress_bar.update(advance)
    
    def scan_port(self, ip, port):
        """改进的端口扫描"""
        if self.stealth_mode:
            return self.stealth_scan_port(ip, port)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.options.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self.common_services.get(port, "未知服务")
                with self.thread_lock:  # 添加线程锁保护
                    self.open_ports.append((port, service))
                    if self.options.verbose:
                        self.progress_bar.write(f"[+] 发现开放端口 {port}/tcp - {service}")
                return True
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass
            self.update_progress()
        return False
    
    def stealth_scan_port(self, ip, port):
        """隐蔽端口扫描"""
        if not SCAPY_AVAILABLE:
            return self.scan_port(ip, port)
            
        try:
            # 使用随机源端口
            sport = RandShort()
            
            # 根据扫描类型选择不同的扫描方式
            if self.options.scan_type == 'SYN':
                ans = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags="S"),
                         timeout=1, verbose=0)
                if ans and ans.haslayer(TCP):
                    if ans[TCP].flags == 0x12:  # SYN-ACK
                        # 发送RST包
                        rst = IP(dst=ip)/TCP(sport=sport, dport=port, flags="R")
                        send(rst, verbose=0)
                        return True
                        
            elif self.options.scan_type == 'FIN':
                ans = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags="F"),
                         timeout=1, verbose=0)
                if not ans:
                    return True
                    
            elif self.options.scan_type == 'NULL':
                ans = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags=""),
                         timeout=1, verbose=0)
                if not ans:
                    return True
                    
            elif self.options.scan_type == 'XMAS':
                ans = sr1(IP(dst=ip)/TCP(sport=sport, dport=port, flags="FPU"),
                         timeout=1, verbose=0)
                if not ans:
                    return True
                    
        except Exception as e:
            if self.options.verbose:
                print(f"[!] 隐蔽扫描失败: {e}")
                
        return False

    def scan_host(self, ip):
        """增强的主机扫描函数"""
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.service_versions = {}
        
        print(f"\n[*] 开始扫描主机: {ip}")
        
        # 修改端口选择逻辑
        if self.options.port_list:
            ports = [int(p.strip()) for p in self.options.port_list.split(',')]
        else:
            # 使用用户指定的端口范围
            ports = range(self.options.start_port, self.options.end_port + 1)
            
            # 如果未指定范围，则使用默认策略
            if self.options.start_port == 1 and self.options.end_port == 1024:
                if self.options.end_port >= 65535:
                    ports = self.port_scan_strategy['full']
                elif self.options.end_port >= 1024:
                    ports = self.port_scan_strategy['common']
                else:
                    ports = self.port_scan_strategy['quick']
        
        # 转换为列表以支持随机化
        ports = list(ports)
        if self.options.randomize:
            random.shuffle(ports)
        
        total_ports = len(ports)
        start_time = time.time()
        
        try:
            print(f"[*] 正在扫描 {total_ports} 个端口...")
            
            # 创建进度条
            self.progress_bar = tqdm(
                total=total_ports,
                desc="扫描进度",
                unit="端口",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            )
            
            # 使用线程池进行扫描
            with ThreadPoolExecutor(max_workers=min(50, total_ports)) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port for port in ports}
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.options.verbose:
                            self.progress_bar.write(f"[!] 扫描出错: {str(e)}")
            
            # 关闭进度条
            self.progress_bar.close()
            
            # 打印结果
            print("\n扫描结果:")
            if self.open_ports:
                for port, service in sorted(self.open_ports):
                    print(f"[+] {port}/tcp 开放 - {service}")
            
            # 添加WAF检测
            if any(port in [80, 443] for port, _ in self.open_ports):
                waf = self.detect_waf(ip, 80 if 80 in [p for p, _ in self.open_ports] else 443)
                if waf:
                    print(f"\n[!] 检测到WAF: {', '.join(waf)}")
            
            # Web应用识别
            web_apps = []
            for port, service in self.open_ports:
                if service.upper() in ['HTTP', 'HTTPS']:
                    apps = self.web_fingerprint(ip, port)
                    if apps:
                        web_apps.extend(apps)
                        
            if web_apps:
                print("\n[+] 发现Web应用:")
                for app, path in web_apps:
                    print(f"  - {app} ({path})")
            
            # 统计信息
            duration = time.time() - start_time
            print(f"\n[*] 扫描完成: 发现 {len(self.open_ports)} 个开放端口")
            print(f"[*] 扫描用时: {duration:.2f} 秒")
            
            return {
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip': ip,
                'duration': duration,
                'open_ports': [(p, s) for p, s in self.open_ports],
                'statistics': {
                    'total': total_ports,
                    'open': len(self.open_ports),
                    'closed': len(self.closed_ports),
                    'filtered': len(self.filtered_ports)
                }
            }
            
        except KeyboardInterrupt:
            if self.progress_bar:
                self.progress_bar.close()
            print("\n[!] 扫描被用户中断")
            return None
        except Exception as e:
            if self.progress_bar:
                self.progress_bar.close()
            print(f"\n[!] 扫描出错: {str(e)}")
            return None

    def detect_waf(self, ip, port):
        """检测WAF"""
        if port not in [80, 443]:
            return None
            
        waf_detected = []
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}"
        
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            if self.use_proxy:
                proxies = {'http': self.use_proxy, 'https': self.use_proxy}
            else:
                proxies = None
                
            import requests
            response = requests.get(url, headers=headers, proxies=proxies, 
                                 verify=False, timeout=5)
            
            # 检查响应头
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for waf, sigs in self.waf_signatures.items():
                for sig in sigs:
                    if any(sig.lower() in v.lower() for v in headers.values()):
                        waf_detected.append(waf)
                        break
            
            return list(set(waf_detected))
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] WAF检测失败: {e}")
            return None

    def web_fingerprint(self, ip, port):
        """Web应用识别"""
        web_apps = []
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{ip}"
        
        headers = {'User-Agent': random.choice(self.user_agents)}
        if self.use_proxy:
            proxies = {'http': self.use_proxy, 'https': self.use_proxy}
        else:
            proxies = None
            
        for app, paths in self.web_fingerprints.items():
            for path in paths:
                try:
                    url = f"{base_url}{path}"
                    response = requests.get(url, headers=headers, proxies=proxies,
                                         verify=False, timeout=5)
                    if response.status_code != 404:
                        web_apps.append((app, path))
                        break
                except:
                    continue
                    
        return web_apps

    def save_scan_results(self, results):
        """保存扫描结果到文件"""
        try:
            filename = f"scan_{results['ip']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"[*] 扫描结果已保存到: {filename}")
        except Exception as e:
            print(f"[!] 保存扫描结果失败: {str(e)}")

    def http_vulnerability_check(self, ip, port):
        """检查HTTP服务的基本漏洞"""
        vulns = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((ip, port)) == 0:
                # 发送HTTP请求
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                # 检查HTTP响应头
                headers = {}
                for line in response.split('\r\n'):
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value
                
                # 检查安全相关的HTTP头
                security_headers = {
                    'x-frame-options': 'clickjacking防护',
                    'x-xss-protection': 'XSS防护',
                    'x-content-type-options': 'MIME类型嗅探防护',
                    'strict-transport-security': 'HSTS',
                    'content-security-policy': 'CSP'
                }
                
                for header, desc in security_headers.items():
                    if header not in headers:
                        vulns.append(f"缺少{desc}头部({header})")
                
                # 检查服务器信息泄露
                if 'server' in headers:
                    vulns.append(f"服务器信息泄露: {headers['server']}")
                
                # 检查是否支持HTTP/2
                if 'HTTP/2' not in response:
                    vulns.append("不支持HTTP/2协议")
                
            sock.close()
            return vulns
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] HTTP漏洞检查失败: {e}")
            return vulns

    def ssh_vulnerability_check(self, ip, port):
        """检查SSH服务的基本漏洞"""
        vulns = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((ip, port)) == 0:
                # 获取SSH Banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # 检查SSH版本
                if 'SSH-1.' in banner:
                    vulns.append("使用不安全的SSH v1协议")
                
                ssh_version = ''
                if 'OpenSSH' in banner:
                    import re
                    version_match = re.search(r'OpenSSH[_-](\d+\.\d+)', banner)
                    if version_match:
                        ssh_version = version_match.group(1)
                        if float(ssh_version) < 7.0:
                            vulns.append(f"使用过时的OpenSSH版本: {ssh_version}")
                
                # 检查弱加密算法
                if any(x in banner.lower() for x in ['3des', 'blowfish', 'arcfour']):
                    vulns.append("支持不安全的加密算法")
            
            sock.close()
            return vulns
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] SSH漏洞检查失败: {e}")
            return vulns

    def ftp_vulnerability_check(self, ip, port):
        """检查FTP服务的基本漏洞"""
        vulns = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((ip, port)) == 0:
                # 获取FTP Banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # 测试匿名登录
                sock.send(b"USER anonymous\r\n")
                resp1 = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.send(b"PASS anonymous@example.com\r\n")
                resp2 = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in resp2:  # 230表示登录成功
                    vulns.append("允许匿名FTP登录")
                
                # 检查FTP服务器版本
                for old_ver in ['wu-2', 'vs-1', 'proftp-1.2']:
                    if old_ver in banner.lower():
                        vulns.append(f"使用过时的FTP服务器版本: {banner.strip()}")
                        break
                
                # 检查明文传输
                if 'TLS' not in banner and 'SSL' not in banner:
                    vulns.append("FTP使用不安全的明文传输")
            
            sock.close()
            return vulns
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] FTP漏洞检查失败: {e}")
            return vulns

    def smb_vulnerability_check(self, ip, port):
        """检查SMB服务的基本漏洞"""
        vulns = []
        try:
            if port == 445 or port == 139:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    vulns.append(f"开放SMB端口({port})，可能存在安全风险")
                    
                    # 尝试获取SMB版本信息
                    # 这里只是基础检查，实际的SMB漏洞检测需要更复杂的协议实现
                    if port == 445:
                        vulns.append("建议禁用SMBv1，使用SMBv2或更高版本")
                sock.close()
            return vulns
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] SMB漏洞检查失败: {e}")
            return vulns

    def active_os_detection(self, ip):
        """主动操作系统检测"""
        if not SCAPY_AVAILABLE:
            return "需要安装Scapy库以支持OS检测"
        
        try:
            # 发送TCP SYN包到已知开放端口
            test_port = self.open_ports[0][0] if self.open_ports else 80
            
            # 构造TCP SYN包
            syn_packet = IP(dst=ip)/TCP(dport=test_port, flags="S")
            response = sr1(syn_packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP):
                ttl = response.ttl
                win_size = response[TCP].window
                
                # 检查操作系统指纹
                for (ttl_sig, win_sig), os_name in self.os_fingerprints.items():
                    if abs(ttl - ttl_sig) <= 5 and abs(win_size - win_sig) <= 100:
                        return os_name
                
                # 基于TTL值的基本判断
                if ttl <= 64:
                    return "可能是Linux/Unix系统 (TTL <= 64)"
                elif ttl <= 128:
                    return "可能是Windows系统 (TTL <= 128)"
                elif ttl <= 255:
                    return "可能是网络设备 (TTL <= 255)"
            
            return "未能确定操作系统"
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] OS检测失败: {e}")
            return "OS检测失败"

    def run_vulnerability_scan(self, ip):
        """执行漏洞扫描"""
        print("\n[*] 开始漏洞扫描...")
        all_vulns = []
        
        for port, service in self.open_ports:
            service = service.upper()
            if service in self.vulnerability_checks:
                vulns = self.vulnerability_checks[service](ip, port)
                if vulns:
                    print(f"\n[!] 发现 {service} ({port}/tcp) 潜在漏洞:")
                    for vuln in vulns:
                        print(f"  - {vuln}")
                    all_vulns.extend(vulns)
        
        # 检查常见的错误配置
        self.check_common_misconfigurations(ip)
        
        if not all_vulns:
            print("\n[+] 未发现明显漏洞")
        else:
            print(f"\n[!] 总计发现 {len(all_vulns)} 个潜在漏洞")
            
        return all_vulns

    def check_common_misconfigurations(self, ip):
        """检查常见的错误配置"""
        # 检查DNS配置
        try:
            if 53 in [p for p, _ in self.open_ports]:
                print("\n[*] 检查DNS配置...")
                # 检查DNS区域传输
                # 这里只是示例，实际实现需要更复杂的DNS协议处理
                print("[*] 建议: 限制DNS区域传输访问")
        except:
            pass
            
        # 检查数据库配置
        for port, service in self.open_ports:
            if service.upper() in ['MYSQL', 'POSTGRESQL', 'MONGODB', 'REDIS']:
                print(f"\n[*] 发现数据库服务 {service} 在端口 {port}")
                print(f"[*] 建议: 确保 {service} 访问限制在特定IP范围")

        # 检查管理接口
        admin_ports = {
            8080: "Web管理接口",
            8443: "安全Web管理接口",
            10000: "Webmin",
            2222: "SSH备用端口",
            2082: "cPanel",
            2083: "cPanel SSL",
            8888: "通用管理端口"
        }
        
        for port, desc in admin_ports.items():
            if port in [p for p, _ in self.open_ports]:
                print(f"\n[!] 发现可能的管理接口: {port}/tcp ({desc})")
                print(f"[*] 建议: 限制管理接口访问，使用强密码和双因素认证")

        # 检查常见IoT端口
        iot_ports = {
            8883: "MQTT",
            1883: "MQTT",
            5683: "CoAP",
            5684: "CoAP/DTLS"
        }
        
        for port, desc in iot_ports.items():
            if port in [p for p, _ in self.open_ports]:
                print(f"\n[!] 发现IoT相关端口: {port}/tcp ({desc})")
                print(f"[*] 建议: 确保IoT设备使用最新固件并正确配置安全选项")

def main():
    """主程序入口"""
    parser = argparse.ArgumentParser(description='BRX SCAN')
    parser.add_argument('target', help='目标IP地址或域名')
    parser.add_argument('-p', '--ports', dest='port_list', help='指定端口列表 (例如: 80,443,8080)')
    parser.add_argument('-s', '--start-port', dest='start_port', type=int, default=1, help='起始端口')
    parser.add_argument('-e', '--end-port', dest='end_port', type=int, default=1024, help='结束端口')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='超时时间(秒)')
    parser.add_argument('-T', '--timing', type=int, choices=[1,2,3,4,5], default=3, help='扫描速度(1-5)')
    parser.add_argument('--type', dest='scan_type', choices=['TCP','SYN','FIN','NULL','XMAS','UDP'], default='TCP', help='扫描类型')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('-f', '--force', action='store_true', help='强制扫描大型网络')
    parser.add_argument('-r', '--randomize', action='store_true', help='随机化端口顺序')
    parser.add_argument('--service-detection', action='store_true', help='服务版本检测')
    parser.add_argument('--os-detection', action='store_true', help='操作系统检测')
    parser.add_argument('--vuln-scan', action='store_true', help='漏洞扫描')
    parser.add_argument('-d', '--discovery', dest='discovery_method', choices=['ping','arp'], default='ping', help='主机发现方法')
    parser.add_argument('--proxy', help='使用代理 (例如: socks5://127.0.0.1:1080)')
    parser.add_argument('--stealth', action='store_true', help='使用隐蔽扫描模式')
    parser.add_argument('--waf-evasion', action='store_true', help='启用WAF绕过技术')
    
    args = parser.parse_args()
    
    print("\n" + "=" * 60)
    print("扫描目标信息：")
    print("-" * 30)
    print(f"目标地址: {args.target}")
    if args.port_list:
        print(f"指定端口: {args.port_list}")
    else:
        print(f"端口范围: {args.start_port}-{args.end_port}")
    print(f"扫描类型: {args.scan_type}")
    print(f"扫描速度: {args.timing}")
    print("=" * 60 + "\n")
    
    try:
        scanner = AdvancedScanner(args.target, args)
        hosts = scanner.network_discovery()
        
        for host in hosts:
            results = scanner.scan_host(host)
            if args.os_detection and scanner.open_ports:
                os_info = scanner.active_os_detection(host)
                print(f"\n[*] 操作系统检测结果: {os_info}")
            
            if args.vuln_scan and scanner.open_ports:
                scanner.run_vulnerability_scan(host)
                
    except KeyboardInterrupt:
        print("\n[!] 扫描被用户中断")
    except Exception as e:
        print(f"\n[!] 扫描出错: {str(e)}")

if __name__ == '__main__':
    main()