import socket
import time
import ipaddress
import concurrent.futures
import struct
import re
import threading
from mcstatus import JavaServer, BedrockServer

# ===================== 全局配置 =====================
# Java 局域网多播
MCAST_GROUP = "224.0.2.60"
MCAST_PORT = 4445
# 基岩版广播配置
SCAN_PORT = 19132
PING_PACKET = b"\x01" + b"\xff" * 8
BROADCAST_TIMEOUT = 1
# 通用参数
SCAN_TIMEOUT = 2
MAX_WORKERS = 50
LISTEN_DURATION = 10
BUF_SIZE = 1024

# 全局共享结果集合 + 去重
LAN_RESULT = []
SEEN_SET = set()
LOCK = threading.Lock()

# ===================== 工具函数 =====================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except:
        pass
    return "0.0.0.0"

def broadcast_addr(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return "255.255.255.255"
        parts[3] = "255"
        return ".".join(parts)
    except:
        return "255.255.255.255"

def parse_ip_range(input_str: str) -> list:
    targets = []
    if "/" in input_str:
        try:
            net = ipaddress.IPv4Network(input_str, strict=False)
            for host in net.hosts():
                targets.append(str(host))
        except Exception:
            print("❌ 无效IP网段")
    else:
        targets.append(input_str)
    return targets

# ===================== 报文原生解析 =====================
def parse_java_lan_packet(data: bytes):
    try:
        text = data.decode("utf-8", errors="ignore")
        ad_match = re.search(r"\[AD\](\d{1,5})\[/AD\]", text)
        if not ad_match:
            return None, None
        port = int(ad_match.group(1))
        motd_match = re.search(r"\[MOTD\](.*?)\[/MOTD\]", text, re.DOTALL)
        motd = motd_match.group(1) if motd_match else "missing no"
        return motd, port
    except Exception:
        return None, None

# ===================== 线程1：监听 Java 多播（独立线程） =====================
def listen_java_multicast():
    global LAN_RESULT, SEEN_SET
    sock_mcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_mcast.settimeout(1.0)
    sock_mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_mcast.bind(("0.0.0.0", MCAST_PORT))

    mreq = socket.inet_aton(MCAST_GROUP) + socket.inet_aton("0.0.0.0")
    sock_mcast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock_mcast.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    start_time = time.time()
    print("✅ Java 多播监听已启动")
    while time.time() - start_time < LISTEN_DURATION:
        try:
            raw_data, (src_ip, _) = sock_mcast.recvfrom(BUF_SIZE)
            motd, game_port = parse_java_lan_packet(raw_data)
            if not motd or not game_port:
                continue

            key = (src_ip, game_port, "Java")
            with LOCK:
                if key in SEEN_SET:
                    continue
                SEEN_SET.add(key)

            # mcstatus 拉取详情
            try:
                server = JavaServer(src_ip, game_port, timeout=SCAN_TIMEOUT)
                status = server.status()
                ping = server.ping()
                item = {
                    "type": "Java",
                    "ip": src_ip,
                    "port": game_port,
                    "motd": status.motd,
                    "version": status.version.name,
                    "online": status.players.online,
                    "max": status.players.max,
                    "ping": round(ping, 2)
                }
                with LOCK:
                    LAN_RESULT.append(item)
                    print(f"🔔 发现 Java 服务器: {src_ip}:{game_port}")
            except Exception:
                continue
        except socket.timeout:
            continue

    sock_mcast.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
    sock_mcast.close()
    print("🛑 Java 多播监听结束")

# ===================== 线程2：监听基岩版广播（独立线程） =====================
def listen_bedrock_broadcast():
    global LAN_RESULT, SEEN_SET
    sock_bed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_bed.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_bed.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_bed.settimeout(BROADCAST_TIMEOUT)

    try:
        sock_bed.bind(("0.0.0.0", SCAN_PORT))
    except Exception as e:
        print(f"❌ 绑定 {SCAN_PORT} 端口失败: {e}")
        print("请关闭占用端口的程序！")
        return

    local_ip = get_local_ip()
    bc_ip = broadcast_addr(local_ip)
    print("✅ 基岩版广播监听已启动")

    # 循环发送探测包，持续发现局域网设备
    start_time = time.time()
    while time.time() - start_time < LISTEN_DURATION:
        # 发送广播探测包
        for _ in range(2):
            sock_bed.sendto(PING_PACKET, (bc_ip, SCAN_PORT))
            time.sleep(0.1)

        # 接收应答
        while True:
            try:
                data, (src_ip, src_port) = sock_bed.recvfrom(4096)
                if data[0] == 0x1C:
                    key = (src_ip, src_port, "Bedrock")
                    with LOCK:
                        if key in SEEN_SET:
                            continue
                        SEEN_SET.add(key)

                    # mcstatus 拉取详情
                    try:
                        server = BedrockServer(src_ip, src_port, timeout=SCAN_TIMEOUT)
                        status = server.status()
                        ver = status.version.name if hasattr(status.version, 'name') else str(status.version)
                        item = {
                            "type": "Bedrock",
                            "ip": src_ip,
                            "port": src_port,
                            "motd": status.motd,
                            "version": ver,
                            "online": status.players.online,
                            "max": status.players.max,
                            "ping": 0
                        }
                        with LOCK:
                            LAN_RESULT.append(item)
                            print(f"🔔 发现 Bedrock 服务器: {src_ip}:{src_port}")
                    except Exception:
                        continue
            except socket.timeout:
                break
    sock_bed.close()
    print("🛑 基岩版广播监听结束")

# ===================== 局域网综合扫描（双线程并行监听） =====================
def discover_lan_servers():
    global LAN_RESULT, SEEN_SET
    # 每次扫描重置
    LAN_RESULT.clear()
    SEEN_SET.clear()

    print("\n--- 并行启动 Java + 基岩版 双监听 ---")
    # 创建并启动两个独立线程
    t1 = threading.Thread(target=listen_java_multicast, daemon=True)
    t2 = threading.Thread(target=listen_bedrock_broadcast, daemon=True)
    t1.start()
    t2.start()

    # 等待两个线程全部执行完毕
    t1.join()
    t2.join()
    return LAN_RESULT

# ===================== 端口区间扫描（已修复 all 并发 + MOTD 美化） =====================
def check_java(ip: str, port: int):
    try:
        s = JavaServer(ip, port, timeout=SCAN_TIMEOUT)
        st = s.status()
        ping = s.ping()
        return {
            "type": "Java",
            "ip": ip,
            "port": port,
            "motd": st.motd,
            "version": st.version.name,
            "online": st.players.online,
            "max": st.players.max,
            "ping": round(ping, 2)
        }
    except Exception:
        return None

def check_bedrock(ip: str, port: int):
    try:
        s = BedrockServer(ip, port, timeout=SCAN_TIMEOUT)
        st = s.status()
        ver = st.version.name if hasattr(st.version, 'name') else str(st.version)
        return {
            "type": "Bedrock",
            "ip": ip,
            "port": port,
            "motd": st.motd,
            "version": ver,
            "online": st.players.online,
            "max": st.players.max,
            "ping": 0
        }
    except Exception:
        return None

def scan_ip_port_range(target_ips: list, port_start: int, port_end: int, scan_mode: str):
    all_tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for ip in target_ips:
            for port in range(port_start, port_end + 1):
                if scan_mode in ("java", "all"):
                    all_tasks.append(pool.submit(check_java, ip, port))
                if scan_mode in ("bedrock", "all"):
                    all_tasks.append(pool.submit(check_bedrock, ip, port))

        result_list = []
        for task in concurrent.futures.as_completed(all_tasks):
            ret = task.result()
            if ret:
                result_list.append(ret)
    return result_list

# ===================== 统一美化输出（解析 MOTD 纯文本） =====================
def print_results(data_list: list):
    print("\n" + "=" * 70)
    print("📊 扫描结果")
    print("=" * 70)
    if not data_list:
        print("未发现任何 Minecraft 服务器")
        print("=" * 70)
        return

    for idx, item in enumerate(data_list, 1):
        if hasattr(item['motd'], 'raw'):
            motd_str = item['motd'].raw
        elif hasattr(item['motd'], 'parse'):
            motd_str = item['motd'].parse()
        else:
            motd_str = str(item['motd'])

        print(f"[{idx}] 类型: {item['type']}")
        print(f"📍 地址: {item['ip']}:{item['port']}")
        print(f"📝 名称: {motd_str}")
        print(f"📦 版本: {item['version']}")
        print(f"👥 在线: {item['online']}/{item['max']}")
        if item["ping"] > 0:
            print(f"⏱️  延迟: {item['ping']} ms")
        print("-" * 70)
    print("=" * 70)

# ===================== 主菜单 =====================
def main():
    print("=" * 60)
    print("MC 服务器扫描工具")
    print("1. 局域网自动发现 (Java + 基岩 并行同时监听)")
    print("2. 指定IP/网段 + 端口区间扫描")
    print("=" * 60)

    while True:
        mode = input("\n请选择功能 [1/2]：").strip()
        if mode in ("1", "2"):
            break
        print("输入错误，请输入 1 或 2")

    if mode == "1":
        # 局域网模式：双线程并行监听，互不阻塞
        print("\n--- 请开启MC局域网世界，等待监听完成 ---")
        lan_data = discover_lan_servers()
        print_results(lan_data)

    else:
        # 端口扫描模式
        host_input = input("\n请输入 IP / 域名 / 网段：").strip()
        target_ips = parse_ip_range(host_input)
        if not target_ips:
            return

        while True:
            try:
                p_start = int(input("输入起始端口：").strip())
                p_end = int(input("输入结束端口：").strip())
                if 1 <= p_start <= p_end <= 65535:
                    break
                print("端口范围必须在 1~65535 之间，且起始 ≤ 结束")
            except ValueError:
                print("请输入合法数字")

        print("\n扫描类型：")
        print("java   - 仅扫描Java版")
        print("bedrock- 仅扫描基岩版")
        print("all    - 同时扫描两种版本")
        scan_mode = input("请选择：").strip().lower()
        if scan_mode not in ("java", "bedrock", "all"):
            scan_mode = "all"

        print(f"\n开始扫描，端口 {p_start} ~ {p_end} ...")
        scan_data = scan_ip_port_range(target_ips, p_start, p_end, scan_mode)
        print_results(scan_data)

    input("\n按回车键退出...")

if __name__ == "__main__":
    main()
