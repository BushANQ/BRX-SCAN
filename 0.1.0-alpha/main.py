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
    from scapy.all import sr1, IP, TCP, UDP, ICMP, ARP, Ether, srp, RandShort
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
        self.progress_bar = None  
        self.thread_lock = threading.Lock()
        
        # 常见服务
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
        
        self.os_fingerprints = {
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
        
        # 常见漏洞库(待完善)
        self.vulnerability_checks = {
            "HTTP": self.http_vulnerability_check,
            "SSH": self.ssh_vulnerability_check,
            "FTP": self.ftp_vulnerability_check,
            "SMB": self.smb_vulnerability_check,
        }
        
        self.port_scan_strategy = {
            'quick': [20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
            'common': [f for f in range(1, 1024)],
            'full': [f for f in range(1, 65536)]
        }
        

        self.max_retries = 2
        self.min_timeout = 0.5
        self.max_timeout = 3.0
        self.adaptive_timing = True 
        self.timing_stats = {'success': 0, 'timeout': 0} 
        

        self.batch_size = {
            1: 10,   
            2: 30,   
            3: 100,  
            4: 300,  
            5: 500
        }[options.timing]
        
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

        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"无法解析主机名: {self.target}")
            sys.exit(1)
    
    def get_interface_ip(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
    
    def network_discovery(self):

        target_ip = self.resolve_hostname()
        

        if '/' not in self.target:
            self.hosts_up.append(target_ip)
            return [target_ip]
        

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
        if '/' not in network:  
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
            
            # 返回目标IP
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
        

        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    
    def arp_scan(self, network):

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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.options.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self.common_services.get(port, "未知服务")
                with self.thread_lock:  # 线程锁保护
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
    
    def scan_host(self, ip):

        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.service_versions = {}
        
        print(f"\n[*] 开始扫描主机: {ip}")
        

        if self.options.port_list:
            ports = [int(p.strip()) for p in self.options.port_list.split(',')]
        else:
            ports = range(self.options.start_port, self.options.end_port + 1)
            if self.options.start_port == 1 and self.options.end_port == 1024:
                if self.options.end_port >= 65535:
                    ports = self.port_scan_strategy['full']
                elif self.options.end_port >= 1024:
                    ports = self.port_scan_strategy['common']
                else:
                    ports = self.port_scan_strategy['quick']
        
        ports = list(ports)
        if self.options.randomize:
            random.shuffle(ports)
        
        total_ports = len(ports)
        start_time = time.time()
        
        try:
            print(f"[*] 正在扫描 {total_ports} 个端口...")
            self.progress_bar = tqdm(
                total=total_ports,
                desc="扫描进度",
                unit="端口",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            )
            with ThreadPoolExecutor(max_workers=min(50, total_ports)) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port for port in ports}
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.options.verbose:
                            self.progress_bar.write(f"[!] 扫描出错: {str(e)}")

            self.progress_bar.close()

            print("\n扫描结果:")
            if self.open_ports:
                for port, service in sorted(self.open_ports):
                    print(f"[+] {port}/tcp 开放 - {service}")

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
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                

                headers = {}
                for line in response.split('\r\n'):
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value
                

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
                

                if 'server' in headers:
                    vulns.append(f"服务器信息泄露: {headers['server']}")
                

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
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
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
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.send(b"USER anonymous\r\n")
                resp1 = sock.recv(1024).decode('utf-8', errors='ignore')
                
                sock.send(b"PASS anonymous@example.com\r\n")
                resp2 = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in resp2:  # 230表示登录成功
                    vulns.append("允许匿名FTP登录")
                for old_ver in ['wu-2', 'vs-1', 'proftp-1.2']:
                    if old_ver in banner.lower():
                        vulns.append(f"使用过时的FTP服务器版本: {banner.strip()}")
                        break

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
                    
                    # 未完成，待完善
                    if port == 445:
                        vulns.append("建议禁用SMBv1，使用SMBv2或更高版本")
                sock.close()
            return vulns
            
        except Exception as e:
            if self.options.verbose:
                print(f"[!] SMB漏洞检查失败: {e}")
            return vulns

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