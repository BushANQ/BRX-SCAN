# DRX-SCAN

一个基于Python的高性能端口扫描工具，支持多线程扫描、服务识别等功能。(有部分功能尚未实现，只有一个大概的框架，请等待完善)

## 主要功能

- 端口扫描(TCP/SYN/FIN/NULL/XMAS/UDP)
- 服务版本检测
- Web应用识别
- WAF检测
- 操作系统检测
- 基本漏洞扫描
- 信息收集(WHOIS/DNS/子域名/SSL证书等)
- 支持代理和隐蔽模式

## 依赖安装

```bash
pip install -r requirements.txt
```

## 使用方法

### 基本扫描
```bash
# 扫描默认端口(1-1024)
python main.py example.com

# 指定端口范围
python main.py example.com -s 1 -e 65535

# 指定特定端口
python main.py example.com -p 80,443,8080
```

### 高级选项
```bash
# 调整扫描速度(1-5)
python main.py example.com -T 4

# 显示详细信息
python main.py example.com -v

# 随机化端口顺序
python main.py example.com -r

# 服务版本检测
python main.py example.com --service-detection
```

## 基本选项:
- `target`: 目标IP地址或域名
- `-p, --ports`: 指定端口列表(例如: 80,443,8080)
- `-s, --start-port`: 起始端口
- `-e, --end-port`: 结束端口
- `-t, --timeout`: 超时时间(秒)
- `-T, --timing`: 扫描速度(1-5)

扫描选项:
- `--type`: 扫描类型(TCP/SYN/FIN/NULL/XMAS/UDP)
- `--service-detection`: 启用服务版本检测
- `--os-detection`: 启用操作系统检测
- `--vuln-scan`: 启用漏洞扫描(暂不可用)
- `-d, --discovery`: 主机发现方法(ping/arp)

高级选项:
- `-v, --verbose`: 显示详细信息
- `-f, --force`: 强制扫描大型网络
- `-r, --randomize`: 随机化端口顺序
- `--stealth`: 使用隐蔽扫描模式
- `--waf-evasion`: 启用WAF绕过技术
- `--info-gathering`: 执行信息收集(默认开启)
- `--proxy`: 使用代理

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-p, --ports` | 指定端口列表 | 无 |
| `-s, --start-port` | 起始端口 | 1 |
| `-e, --end-port` | 结束端口 | 1024 |
| `-t, --timeout` | 超时时间(秒) | 1.0 |
| `-T, --timing` | 扫描速度(1-5) | 3 |
| `-v, --verbose` | 显示详细信息 | False |
| `-r, --randomize` | 随机化端口顺序 | False |
| `-f, --force` | 强制扫描大型网络 | False |

## 扫描速度说明

- T1: 极慢 - 最少资源占用，最隐蔽
- T2: 慢速 - 低资源占用
- T3: 正常 - 默认扫描速度
- T4: 快速 - 高性能主机推荐
- T5: 极快 - 可能导致结果不准确

## 0.4.0-alpha输出示例
```bash
============================================================
扫描目标信息：
------------------------------
目标地址: xx.cn
端口范围: 1-1024
扫描类型: TCP
扫描速度: 3
============================================================


██████╗ ██████╗ ██╗  ██╗    ███████╗ ██████╗ █████╗ ██╗   ██╗
██╔══██╗██╔══██╗╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗██║   ██║
██║  ██╗██████╔╝ ╚███╔╝     ███████╗██║     ██████╔╝██║   ██║
██║  ██╗██╔══██╗ ██╔██╗     ╚════██║██║     ██╔══██╗██║   ██║
██████╔╝██║  ██║██╔╝ ██╗    ███████║╚██████╗██║  ██║╚██████╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝
                                                  作者:BushSEC


端口扫描工具
==================================================

[*] 目标地址: xx.cn
[*] 解析地址: xx.xx.xx.xx

============================================================
[*] 正在扫描主机: xx.xx.xx.xx
============================================================

[*] 开始执行信息收集...

[*] 开始信息收集...
[*] 正在查询Whois信息...
[+] Whois信息:
{
  "域名": "xx.cn",
  "注册ID": "2024xxxxxxxxxxxxxxxxxxx-cn",
  "域名状态": "ok\nRegistrant",
  "注册人": "xxx",
  "注册邮箱": "xxxx@qq.com",
  "注册商": "阿里云计算有限公司（万网）",
  "域名服务器": [
    "xx.xx.xxx.com",
    "xx.xx.xxx.com"
  ],
  "创建时间": "xxxx-xx-xx xx:xx:xx",
  "过期时间": "xxxx-xx-xx xx.xx.xx",
  "DNSSEC": "signedDelegation"
}
[+] CORS配置:
{
  "http://xx.xx.xx.xx": {
    "Access-Control-Allow-Origin": null,
    "Access-Control-Allow-Credentials": null,
    "Access-Control-Allow-Methods": null,
    "Access-Control-Allow-Headers": null
  }
}
[+] HTTP响应头:
{
  "http://xx.xx.xx.xx": {
    "Date": "Wed, 02 Apr 2025 04:45:57 GMT",
    "Content-Type": "text/html; charset=UTF-8",
    "Transfer-Encoding": "chunked",
    "Connection": "close",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
    "Expires": "Thu, 01 Jan 1970 00:00:01 GMT",
    "Vary": "Accept-Encoding",
    "Server": "cloudflare",
    "CF-RAY": "929dae04dd4a66a8-AMS",
    "Content-Encoding": "gzip"
  }
}
[*] 信息收集完成


[*] 开始扫描主机: xx.xx.xx.xx
[*] 正在扫描 1023 个端口...
扫描进度: 100%|███████████████████████████████████████| 1023/1023 [00:21<00:00]

扫描结果:
[+] 80/tcp 开放 - HTTP
[+] 443/tcp 开放 - HTTPS

[*] 扫描完成: 发现 2 个开放端口
[*] 扫描用时: 21.58 秒

[*] 操作系统检测结果: 未能确定操作系统
[*] 扫描结果已保存到: scan_ip(xx.xx.xx.xx)_20250402_124626.json
```


## 注意事项

1. SYN、FIN、NULL、XMAS扫描需要root/管理员权限
2. 高速扫描可能触发目标主机的IDS/IPS系统
3. 建议在授权环境下使用
4. 部分功能需要安装scapy库

