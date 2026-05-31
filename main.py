import flet as ft
import socket
import time
import ipaddress
import concurrent.futures
import re
import threading
from mcstatus import JavaServer, BedrockServer

# ===================== 全局配置 =====================
MCAST_GROUP = "224.0.2.60"
MCAST_PORT = 4445
SCAN_PORT = 19132
PING_PACKET = b"\x01" + b"\xff" * 8
BROADCAST_TIMEOUT = 1
SCAN_TIMEOUT = 2
MAX_WORKERS = 50
LISTEN_DURATION = 10
BUF_SIZE = 1024

LAN_RESULT = []
SEEN_SET = set()
LOCK = threading.Lock()

# ===================== 工具函数 =====================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("1.1.1.1", 8))
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
            return []
    else:
        targets.append(input_str)
    return targets

def parse_java_lan_packet(data: bytes):
    try:
        text = data.decode("utf-8", errors="ignore")
        ad_match = re.search(r"\[AD\](\d{1,5})\[/AD\]", text)
        if not ad_match:
            return None, None
        port = int(ad_match.group(1))
        motd_match = re.search(r"\[MOTD\](.*?)\[/MOTD\]", text, re.DOTALL)
        motd = motd_match.group(1) if motd_match else "No MOTD"
        return motd, port
    except Exception:
        return None, None

# ===================== 扫描核心 =====================
def listen_java_multicast():
    global LAN_RESULT, SEEN_SET
    sock_mcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_mcast.settimeout(1.0)
    sock_mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_mcast.bind(("0.0.0.0", MCAST_PORT))
    mreq = socket.inet_aton(MCAST_GROUP) + socket.inet_aton("0.0.0.0")
    sock_mcast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    start_time = time.time()
    while time.time() - start_time < LISTEN_DURATION:
        try:
            raw_data, (src_ip, _) = sock_mcast.recvfrom(BUF_SIZE)
            motd, game_port = parse_java_lan_packet(raw_data)
            if not motd or not game_port:
                continue
            key = (src_ip, game_port, "Java")
            with LOCK:
                if key in SEEN_SET: continue
                SEEN_SET.add(key)
            try:
                server = JavaServer(src_ip, game_port, timeout=SCAN_TIMEOUT)
                status = server.status()
                ping = server.ping()
                item = {
                    "type": "Java", "ip": src_ip, "port": game_port,
                    "motd": str(status.motd), "version": status.version.name,
                    "online": status.players.online, "max": status.players.max, "ping": round(ping, 2)
                }
                with LOCK: LAN_RESULT.append(item)
            except:
                continue
        except socket.timeout:
            continue
    sock_mcast.close()

def listen_bedrock_broadcast():
    global LAN_RESULT, SEEN_SET
    sock_bed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_bed.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock_bed.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_bed.settimeout(BROADCAST_TIMEOUT)
    try:
        sock_bed.bind(("0.0.0.0", SCAN_PORT))
    except:
        return
    local_ip = get_local_ip()
    bc_ip = broadcast_addr(local_ip)
    start_time = time.time()
    while time.time() - start_time < LISTEN_DURATION:
        for _ in range(2):
            sock_bed.sendto(PING_PACKET, (bc_ip, SCAN_PORT))
            time.sleep(0.1)
        while True:
            try:
                data, (src_ip, src_port) = sock_bed.recvfrom(4096)
                if data[0] == 0x1C:
                    key = (src_ip, src_port, "Bedrock")
                    with LOCK:
                        if key in SEEN_SET: continue
                        SEEN_SET.add(key)
                    try:
                        server = BedrockServer(src_ip, src_port, timeout=SCAN_TIMEOUT)
                        status = server.status()
                        ver = status.version.name if hasattr(status.version, 'name') else str(status.version)
                        item = {
                            "type": "Bedrock", "ip": src_ip, "port": src_port,
                            "motd": str(status.motd), "version": ver,
                            "online": status.players.online, "max": status.players.max, "ping": 0
                        }
                        with LOCK: LAN_RESULT.append(item)
                    except:
                        continue
            except socket.timeout:
                break
    sock_bed.close()

def discover_lan_servers():
    global LAN_RESULT, SEEN_SET
    LAN_RESULT.clear()
    SEEN_SET.clear()
    t1 = threading.Thread(target=listen_java_multicast, daemon=True)
    t2 = threading.Thread(target=listen_bedrock_broadcast, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return LAN_RESULT

def check_java(ip: str, port: int):
    try:
        s = JavaServer(ip, port, timeout=SCAN_TIMEOUT)
        st = s.status()
        ping = s.ping()
        return {
            "type": "Java", "ip": ip, "port": port,
            "motd": str(st.motd), "version": st.version.name,
            "online": st.players.online, "max": st.players.max, "ping": round(ping, 2)
        }
    except:
        return None

def check_bedrock(ip: str, port: int):
    try:
        s = BedrockServer(ip, port, timeout=SCAN_TIMEOUT)
        st = s.status()
        ver = st.version.name if hasattr(st.version, 'name') else str(st.version)
        return {
            "type": "Bedrock", "ip": ip, "port": port,
            "motd": str(st.motd), "version": ver,
            "online": st.players.online, "max": st.players.max, "ping": 0
        }
    except:
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
        if ret: result_list.append(ret)
    return result_list

# ===================== 你要的界面 =====================
def main(page: ft.Page):
    page.title = "MC 扫描工具"
    page.window_width = 400
    page.window_height = 650
    page.padding = 15
    page.spacing = 10
    page.scroll = ft.ScrollMode.AUTO

    # 全局状态
    scan_mode = ft.Ref[str]("all")

    # 结果区域
    result_list = ft.ListView(height=280, spacing=3)

    # 输入控件
    input_ip = ft.TextField(label="IP/域名/网段", value="192.168.1.0/24", expand=True)
    input_port_start = ft.TextField(label="起始端口", value="25565")
    input_port_end = ft.TextField(label="结束端口", value="25565", expand=True)

    # 自定义扫描面板（默认隐藏）
    custom_panel = ft.Column(
        [
            ft.Row([input_ip, ft.ElevatedButton("确定", on_click=lambda e: start_scan())]),
            input_port_start,
            ft.Row([input_port_end, ft.ElevatedButton("确定", on_click=lambda e: start_scan())]),
            ft.Text("扫描类型："),
            ft.Row([
                ft.ElevatedButton("Java", on_click=lambda e: set_mode("java")),
                ft.ElevatedButton("Bedrock", on_click=lambda e: set_mode("bedrock")),
                ft.ElevatedButton("All", on_click=lambda e: set_mode("all")),
            ], spacing=8),
        ],
        visible=False,
        spacing=10
    )

    def set_mode(m):
        scan_mode.current = m
        result_list.controls.append(ft.Text(f"已选择：{m}", color=ft.colors.GREEN))
        page.update()

    def clear_result():
        result_list.controls.clear()
        page.update()

    def add_result(item):
        txt = ft.Text(
            f"[{item['type']}] {item['ip']}:{item['port']}\n"
            f"MOTD: {item['motd']}\n"
            f"版本: {item['version']}  在线: {item['online']}/{item['max']}"
        )
        result_list.controls.append(txt)
        result_list.controls.append(ft.Divider(height=1))
        page.update()

    # 局域网扫描
    def run_lan(e):
        custom_panel.visible = False
        clear_result()
        result_list.controls.append(ft.Text("正在扫描局域网...", color=ft.colors.BLUE))
        page.update()

        def task():
            data = discover_lan_servers()
            clear_result()
            if not data:
                result_list.controls.append(ft.Text("未发现服务器", color=ft.colors.GREY))
            else:
                for item in data:
                    add_result(item)
            page.update()
        threading.Thread(target=task, daemon=True).start()

    # 指定IP扫描
    def show_custom(e):
        custom_panel.visible = True
        page.update()

    def start_scan():
        clear_result()
        ip_str = input_ip.value.strip()
        p_s = input_port_start.value.strip()
        p_e = input_port_end.value.strip()

        if not ip_str or not p_s or not p_e:
            result_list.controls.append(ft.Text("请填写完整", color=ft.colors.RED))
            page.update()
            return

        try:
            p1 = int(p_s)
            p2 = int(p_e)
        except:
            result_list.controls.append(ft.Text("端口必须是数字", color=ft.colors.RED))
            page.update()
            return

        ips = parse_ip_range(ip_str)
        if not ips:
            result_list.controls.append(ft.Text("IP格式错误", color=ft.colors.RED))
            page.update()
            return

        result_list.controls.append(ft.Text("扫描中...", color=ft.colors.BLUE))
        page.update()

        def task():
            data = scan_ip_port_range(ips, p1, p2, scan_mode.current)
            clear_result()
            if not data:
                result_list.controls.append(ft.Text("未找到服务器", color=ft.colors.GREY))
            else:
                for item in data:
                    add_result(item)
            page.update()
        threading.Thread(target=task, daemon=True).start()

    # 界面布局（完全按你的图）
    page.add(
        ft.Text("MC 扫描工具", size=22, weight=ft.FontWeight.BOLD),
        ft.Row([
            ft.ElevatedButton("局域网", on_click=run_lan, expand=True),
            ft.ElevatedButton("指定IP", on_click=show_custom, expand=True),
        ], spacing=10),
        custom_panel,
        ft.Divider(),
        ft.Text("扫描结果：", size=16, weight=ft.FontWeight.BOLD),
        result_list
    )

if __name__ == "__main__":
    ft.app(target=main)
