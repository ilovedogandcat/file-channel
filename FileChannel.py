#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FileChannel —— 两台电脑之间的“文件通道”

特点
  * 两台机器各运行一份，谁都可以给谁发文件（点对点，不需要中转服务器）
  * 支持从资源管理器直接把文件/文件夹拖进窗口
  * 对方会弹出提示，可选择“接受 / 拒绝”
  * 同一个程序也支持命令行模式（--serve / --send），便于脚本化或互相排查
  * 局域网 / Radmin VPN / Tailscale 均可，只要有 IP 能互相 ping 通

依赖：Python 3.8+（标准库，无需第三方包；打包后的 exe 不需要 Python）
"""

from __future__ import annotations

import ctypes
import http.client
import http.server
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import uuid

APP_NAME = "FileChannel"
APP_VERSION = "1.0"
DEFAULT_TCP_PORT = 8765
DEFAULT_UDP_PORT = 8766
CHUNK_SIZE = 1 << 20                 # 1 MiB
OFFER_WAIT_SENDER = 200.0            # 发送方等待对方“接受/拒绝”的最长时间（秒）
OFFER_COUNTDOWN = 60                 # 接收方弹窗倒计时，超时自动拒绝（秒）
TOKEN_TTL = 30 * 60                  # 接收许可有效期（秒）
PING_TIMEOUT = 5.0

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".file_channel")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def human_size(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def safe_name(name: str) -> str:
    """把对方给出的文件名变成安全的本地文件名（去掉路径、非法字符）。"""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip().strip(".")
    if not name or name in (".", ".."):
        name = "unnamed"
    return name[:180]


def safe_relpath(rel: str):
    """把对方给出的相对路径拆成安全的各级名字（丢掉空段、".." 和绝对路径前缀）。"""
    parts = []
    for seg in re.split(r"[\\/]+", rel or ""):
        seg = seg.strip()
        if not seg or seg in (".", ".."):
            continue
        parts.append(safe_name(seg))
    return parts


def unique_path(dirpath: str, filename: str) -> str:
    base, ext = os.path.splitext(filename)
    cand = os.path.join(dirpath, filename)
    i = 1
    while os.path.exists(cand):
        cand = os.path.join(dirpath, f"{base} ({i}){ext}")
        i += 1
    return cand


def open_folder(path: str) -> None:
    try:
        if os.path.isfile(path):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            os.startfile(os.path.normpath(path))  # noqa: S606
    except Exception:
        pass


def _run_hidden(cmd):
    """运行命令并取回文本输出（不弹黑框）。"""
    kwargs = {"capture_output": True, "text": True}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        kwargs["encoding"] = "gbk"
        kwargs["errors"] = "ignore"
    return subprocess.run(cmd, **kwargs)


def local_ipv4_list():
    """返回 [(ip, netmask)]，尽量覆盖网线、Wi-Fi、Radmin VPN、Tailscale 等。"""
    out = []
    seen = set()
    try:
        r = _run_hidden(["ipconfig"])
        lines = (r.stdout or "").splitlines()
        ip = None
        for line in lines:
            m_ip = re.search(r"IPv4[^:：]*[:：]\s*([0-9.]+)", line, re.I)
            if m_ip:
                ip = m_ip.group(1)
                continue
            m_mask = re.search(r"(?:Subnet Mask|子网掩码)[^:：]*[:：]\s*([0-9.]+)", line, re.I)
            if m_mask and ip:
                if ip not in seen:
                    seen.add(ip)
                    out.append((ip, m_mask.group(1)))
                ip = None
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in seen and not ip.startswith("127."):
                seen.add(ip)
                out.append((ip, "255.255.255.0"))
    except Exception:
        pass
    # 优先显示可用的对外地址
    def rank(item):
        ip = item[0]
        if ip.startswith("127."):
            return 9
        if ip.startswith("169.254."):
            return 8
        if ip.startswith("26."):
            return 2      # Radmin VPN
        if ip.startswith("100."):
            return 3      # Tailscale
        return 1          # 普通局域网/校园网
    return sorted(out, key=rank)


def broadcast_addrs(ip_mask_list):
    res = set()
    for ip, mask in ip_mask_list:
        try:
            ip_i = int.from_bytes(socket.inet_aton(ip), "big")
            mk_i = int.from_bytes(socket.inet_aton(mask), "big")
            bc = ip_i | (~mk_i & 0xFFFFFFFF)
            res.add(socket.inet_ntoa(bc.to_bytes(4, "big")))
        except Exception:
            continue
    res.add("255.255.255.255")
    return sorted(res)


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "name": "",
    "tcp_port": DEFAULT_TCP_PORT,
    "udp_port": DEFAULT_UDP_PORT,
    "pin": "",
    "receive_dir": "",
    "peers": [],            # [{"label":.., "host":.., "port":.., "pin":..}]
    "auto_accept": [],      # 允许自动接受的主机名/IP
    "last_peer": "",
}


class Config:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data.update(json.load(f) or {})
        except Exception:
            pass
        if not self.data.get("name"):
            self.data["name"] = socket.gethostname()
        if not self.data.get("receive_dir"):
            self.data["receive_dir"] = os.path.join(
                os.path.expanduser("~"), "Desktop", "文件通道接收")

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def __getitem__(self, k):
        return self.data.get(k)

    def __setitem__(self, k, v):
        self.data[k] = v


# --------------------------------------------------------------------------
# 传输会话
# --------------------------------------------------------------------------
class Offer:
    """一次“我要给你发文件”的请求。"""

    def __init__(self, files, sender, peer_ip, peer_name=None):
        self.id = uuid.uuid4().hex[:12]
        self.files = files                 # [{"name": str, "size": int}]
        self.sender = sender or peer_ip
        self.peer_ip = peer_ip
        self.peer_name = peer_name or sender or peer_ip
        self.created = time.time()
        self.event = threading.Event()
        self.decision = None               # 'accept' / 'reject' / 'timeout'
        self.dest_dir = None
        self.accepted_files = {}           # name -> saved path

    @property
    def total_size(self):
        return sum(int(f.get("size") or 0) for f in self.files)

    def decide(self, decision):
        if self.decision is None:
            self.decision = decision
            self.event.set()


# --------------------------------------------------------------------------
# 服务端（接收方）
# --------------------------------------------------------------------------
class ChannelState:
    """服务器与界面之间共享的状态。"""

    def __init__(self, config, hooks, log=None):
        self.config = config
        self.hooks = hooks
        self.log = log or (lambda msg: None)
        self.tokens = {}                   # token -> (Offer, expire_ts)
        self.lock = threading.Lock()
        self.stopped = False

    # --- 由 HTTP 线程调用 -------------------------------------------------
    def ask_offer(self, offer: Offer) -> str:
        """把请求交给界面（或命令行），等待“接受/拒绝”。"""
        try:
            if offer.sender in (self.config["auto_accept"] or []):
                return "accept"
            decision = self.hooks.ask_offer(offer)
        except Exception:
            traceback.print_exc()
            decision = "reject"
        return decision or "reject"

    def issue_token(self, offer: Offer) -> str:
        token = secrets.token_urlsafe(18)
        with self.lock:
            self.tokens[token] = (offer, time.time() + TOKEN_TTL)
        return token

    def take_token(self, token: str):
        with self.lock:
            item = self.tokens.get(token)
            if not item:
                return None
            offer, exp = item
            if exp < time.time():
                self.tokens.pop(token, None)
                return None
            return offer

    def revoke_token(self, token: str):
        with self.lock:
            self.tokens.pop(token, None)

    def report_progress(self, offer, fname, done, total, final=False):
        try:
            self.hooks.progress(offer, fname, done, total, final)
        except Exception:
            pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{APP_NAME}/{APP_VERSION}"

    # 静音默认日志
    def log_message(self, fmt, *args):
        pass

    # ---- 基础工具 -------------------------------------------------------
    @property
    def state(self) -> ChannelState:
        return self.server.state  # type: ignore[attr-defined]

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _read_body(self, limit=8 << 20):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return b""
        if n > limit:
            raise ValueError("body too large")
        return self.rfile.read(n)

    def _pin_ok(self) -> bool:
        need = (self.state.config["pin"] or "").strip()
        if not need:
            return True
        got = (self.headers.get("X-Pin") or "").strip()
        return got == need

    # ---- GET ------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/ping":
            return self._json({
                "app": APP_NAME,
                "version": APP_VERSION,
                "name": self.state.config["name"],
                "host": socket.gethostname(),
                "port": self.state.config["tcp_port"],
                "pin_required": bool((self.state.config["pin"] or "").strip()),
                "time": time.time(),
            })
        if path == "/":
            return self._json({"app": APP_NAME, "version": APP_VERSION,
                               "hint": "用 FileChannel 客户端连接本机"})
        return self._json({"error": "not found"}, 404)

    # ---- POST -----------------------------------------------------------
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/offer":
                return self._offer()
            if path == "/upload":
                return self._upload()
        except Exception as e:
            traceback.print_exc()
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        return self._json({"error": "not found"}, 404)

    def _offer(self):
        if not self._pin_ok():
            return self._json({"accept": False, "reason": "pin"}, 403)
        data = json.loads(self._read_body().decode("utf-8") or "{}")
        files = data.get("files") or []
        if not files:
            return self._json({"accept": False, "reason": "empty"}, 400)
        peer_ip = self.client_address[0]
        offer = Offer(files, data.get("from") or peer_ip, peer_ip, data.get("from"))
        self.state.log(f"收到来自 {offer.sender} ({peer_ip}) 的请求："
                       f"{len(files)} 个文件，共 {human_size(offer.total_size)}")
        decision = self.state.ask_offer(offer)
        if decision != "accept":
            self.state.log(f"已{('拒绝' if decision == 'reject' else '忽略（超时）')} "
                           f"{offer.sender} 的传输请求")
            return self._json({"accept": False, "reason": decision})
        if not offer.dest_dir:
            folder = f"{safe_name(offer.sender)}_{time.strftime('%Y%m%d_%H%M%S')}"
            offer.dest_dir = os.path.join(self.state.config["receive_dir"], folder)
        # 先把目录结构建好（包括只有空目录的情况），这样文件夹层次能原样还原
        for f in offer.files:
            parts = safe_relpath(f.get("rel") or f.get("name") or "")
            if not parts:
                continue
            try:
                if f.get("dir"):
                    os.makedirs(os.path.join(offer.dest_dir, *parts), exist_ok=True)
                elif len(parts) > 1:
                    os.makedirs(os.path.join(offer.dest_dir, *parts[:-1]), exist_ok=True)
            except Exception as e:
                self.state.log(f"[警告] 建立目录失败 {'/'.join(parts)}：{e}")
        token = self.state.issue_token(offer)
        self.state.log(f"已接受 {offer.sender} 的传输请求，开始接收…")
        return self._json({"accept": True, "token": token, "offer": offer.id})

    def _upload(self):
        if not self._pin_ok():
            return self._json({"ok": False, "error": "pin"}, 403)
        token = self.headers.get("X-Token") or ""
        offer = self.state.take_token(token)
        if offer is None:
            return self._json({"ok": False, "error": "token"}, 403)
        raw_rel = (urllib.parse.unquote(self.headers.get("X-Rel-Path") or "")
                   or urllib.parse.unquote(self.headers.get("X-File-Name") or ""))
        parts = safe_relpath(raw_rel) or ["unnamed"]
        fname = "/".join(parts)
        target_dir = os.path.join(offer.dest_dir, *parts[:-1])
        os.makedirs(target_dir, exist_ok=True)
        target = unique_path(target_dir, parts[-1])
        base_dir = os.path.abspath(offer.dest_dir)
        if not os.path.abspath(target).startswith(base_dir + os.sep):
            return self._json({"ok": False, "error": "bad path"}, 400)
        total = int(self.headers.get("Content-Length") or 0)
        done = 0
        last_report = 0.0
        try:
            with open(target, "wb") as f:
                remaining = total
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    remaining -= len(chunk)
                    now = time.time()
                    if now - last_report > 0.2:
                        last_report = now
                        self.state.report_progress(offer, fname, done, total)
        except Exception as e:
            self.state.log(f"[错误] 接收 {fname} 失败：{e}")
            return self._json({"ok": False, "error": str(e)}, 500)
        if total and done != total:
            self.state.log(f"[错误] {fname} 传输不完整（{done}/{total} 字节）")
            return self._json({"ok": False, "error": "incomplete"}, 400)
        offer.accepted_files[fname] = target
        self.state.report_progress(offer, fname, done or total, total or done, final=True)
        self.state.log(f"已保存：{target}（{human_size(done)}）")
        return self._json({"ok": True, "path": target, "name": fname})


class ChannelServer(threading.Thread):
    def __init__(self, config, hooks, port=None, log=None):
        super().__init__(daemon=True)
        self.config = config
        self.state = ChannelState(config, hooks, log=log)
        self.port = int(port or config["tcp_port"])
        self.httpd = None
        self.ready = threading.Event()
        self.error = None

    def run(self):
        try:
            self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
            self.httpd.state = self.state          # type: ignore[attr-defined]
            self.httpd.daemon_threads = True
        except Exception as e:
            self.error = e
            self.ready.set()
            return
        self.ready.set()
        self.httpd.serve_forever(poll_interval=0.3)

    def stop(self):
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 发现（局域网/虚拟局域网内自动找对方）
# --------------------------------------------------------------------------
class Discovery(threading.Thread):
    def __init__(self, config, on_peer, log=None, udp_port=None):
        super().__init__(daemon=True)
        self.config = config
        self.on_peer = on_peer
        self.log = log or (lambda m: None)
        self.udp_port = int(udp_port or config["udp_port"])
        self.stop_flag = threading.Event()
        self.sock = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind(("", self.udp_port))
            s.settimeout(1.0)
            self.sock = s
        except Exception as e:
            self.log(f"[提示] 自动发现不可用（UDP {self.udp_port}）：{e}")
            return
        ips = local_ipv4_list()
        targets = broadcast_addrs(ips)
        last = 0.0
        while not self.stop_flag.is_set():
            try:
                now = time.time()
                if now - last > 3.0:
                    last = now
                    payload = json.dumps({
                        "app": APP_NAME, "name": self.config["name"],
                        "host": socket.gethostname(), "port": self.config["tcp_port"],
                    }, ensure_ascii=False).encode("utf-8")
                    for b in targets:
                        try:
                            self.sock.sendto(payload, (b, self.udp_port))
                        except Exception:
                            pass
                data, addr = self.sock.recvfrom(4096)
                info = json.loads(data.decode("utf-8", "ignore"))
                if info.get("app") != APP_NAME:
                    continue
                if addr[0] in ("127.0.0.1",) or info.get("host") == socket.gethostname():
                    continue
                self.on_peer(info.get("name") or addr[0], addr[0],
                             int(info.get("port") or DEFAULT_TCP_PORT))
            except socket.timeout:
                continue
            except Exception:
                continue

    def stop(self):
        self.stop_flag.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 发送端
# --------------------------------------------------------------------------
class Source:
    """一个顶层拖入项：单个文件，或一个文件夹（递归展开成若干文件）。"""

    def __init__(self, top):
        self.top = os.path.abspath(top)
        self.is_dir = os.path.isdir(self.top)
        self.display = os.path.basename(self.top.rstrip("\\/")) or self.top
        self.files = []          # [(本地路径, 相对路径, 字节数)]
        self.dirs = []           # 空目录的相对路径
        self.size = 0

    def scan(self):
        """展开文件夹：不打包、不产生临时文件。"""
        if self.is_dir:
            parent = os.path.dirname(self.top)
            for root, dirs, files in os.walk(self.top):
                if not files and not dirs:
                    self.dirs.append(os.path.relpath(root, parent))
                for fn in files:
                    full = os.path.join(root, fn)
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        continue
                    self.files.append((full, os.path.relpath(full, parent), size))
                    self.size += size
        elif os.path.isfile(self.top):
            size = os.path.getsize(self.top)
            self.files.append((self.top, os.path.basename(self.top), size))
            self.size = size
        return self


class Sender(threading.Thread):
    """发送一批文件 / 文件夹（后台线程）。

    文件夹按目录结构**逐个文件直传**，不再压成 zip：立刻开始、不额外占磁盘、不受系统盘空间限制。
    """

    def __init__(self, paths, host, port, pin="", my_name="", hooks=None, log=None):
        super().__init__(daemon=True)
        self.paths = list(paths)
        self.host = host
        self.port = int(port)
        self.pin = pin or ""
        self.my_name = my_name or socket.gethostname()
        self.hooks = hooks
        self.log = log or (lambda m: None)
        self.cancelled = False
        self.sources = []

    def prepare(self):
        """扫描顶层项，返回 [Source]（只读元数据，不写任何临时文件）。"""
        sources = []
        for p in self.paths:
            if not os.path.exists(p):
                self.log(f"[跳过] 不存在：{p}")
                continue
            src = Source(p).scan()
            if src.is_dir:
                self.log(f"扫描文件夹 {src.top}：{len(src.files)} 个文件，{human_size(src.size)}"
                         + (f"，{len(src.dirs)} 个空目录" if src.dirs else ""))
            sources.append(src)
        self.sources = sources
        if sources and self.hooks and hasattr(self.hooks, "prepared"):
            try:
                self.hooks.prepared([(s.display, s.size, len(s.files)) for s in sources])
            except Exception:
                pass
        return sources

    def _post_json(self, conn, path, obj, timeout):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        conn.timeout = timeout
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
            "X-Pin": self.pin,
        })
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, json.loads(data.decode("utf-8") or "{}")

    def run(self):
        try:
            sources = self.prepare()
            if not sources:
                self.log("[错误] 没有可发送的文件")
                return
            nfiles = sum(len(s.files) for s in sources)
            total = sum(s.size for s in sources)
            self.log(f"连接 {self.host}:{self.port} …（{nfiles} 个文件，共 {human_size(total)}）")

            # 1) 先握手，确认对面是 FileChannel
            try:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=PING_TIMEOUT)
                conn.request("GET", "/ping")
                resp = conn.getresponse()
                info = json.loads(resp.read().decode("utf-8") or "{}")
                conn.close()
            except Exception as e:
                self.log(f"[失败] 连不上 {self.host}:{self.port} —— {e}")
                if self.hooks:
                    self.hooks.finished(False, f"连接失败：{e}")
                return
            if info.get("app") != APP_NAME:
                self.log(f"[失败] {self.host}:{self.port} 不是 FileChannel 服务")
                if self.hooks:
                    self.hooks.finished(False, "对方不是 FileChannel")
                return
            self.log(f"已连接：{info.get('name')}（{info.get('host')}）")

            # 2) 发出请求，等对方点“接受”
            try:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=OFFER_WAIT_SENDER + 30)
                files_payload = []
                for s in sources:
                    for _local, rel, size in s.files:
                        files_payload.append({"name": rel, "rel": rel, "size": size})
                    for d in s.dirs:
                        files_payload.append({"name": d, "rel": d, "size": 0, "dir": True})
                status, ans = self._post_json(conn, "/offer", {
                    "from": self.my_name,
                    "files": files_payload,
                }, OFFER_WAIT_SENDER + 30)
                conn.close()
            except Exception as e:
                self.log(f"[失败] 发送请求出错：{e}")
                if self.hooks:
                    self.hooks.finished(False, str(e))
                return
            reason_map = {"pin": "对方口令不匹配", "reject": "对方拒绝接收",
                          "timeout": "对方未在限时内响应", "empty": "请求为空"}
            if not ans.get("accept"):
                msg = reason_map.get(ans.get("reason"), ans.get("reason") or "被拒绝")
                self.log(f"[已取消] {msg}")
                if self.hooks:
                    self.hooks.finished(False, msg)
                return
            token = ans.get("token")
            self.log("对方已接受，开始传输…")

            # 3) 逐个文件上传（复用同一条连接；相对路径带给对方以还原目录结构）
            ok_count = 0
            conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
            for si, s in enumerate(sources):
                done_bytes = 0
                for local, rel, size in s.files:
                    if self.cancelled:
                        self.log("[已取消] 用户中止")
                        break
                    try:
                        conn.putrequest("POST", "/upload")
                        conn.putheader("X-Pin", self.pin)
                        conn.putheader("X-Token", token)
                        conn.putheader("X-Rel-Path", urllib.parse.quote(rel))
                        conn.putheader("Content-Length", str(size))
                        conn.endheaders()
                        sent = 0
                        last = 0.0
                        with open(local, "rb") as f:
                            while True:
                                chunk = f.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                conn.send(chunk)
                                sent += len(chunk)
                                now = time.time()
                                if now - last > 0.2 or sent == size:
                                    last = now
                                    if self.hooks:
                                        self.hooks.progress(si, s.display,
                                                            done_bytes + sent, s.size)
                        resp = conn.getresponse()
                        body = json.loads(resp.read().decode("utf-8") or "{}")
                        if body.get("ok"):
                            ok_count += 1
                        else:
                            self.log(f"[失败] {rel}：{body.get('error')}")
                    except Exception as e:
                        self.log(f"[失败] {rel}：{e}")
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
                    done_bytes += size
                    if self.hooks:
                        self.hooks.progress(si, s.display, done_bytes, s.size)
                if self.cancelled:
                    break
            try:
                conn.close()
            except Exception:
                pass
            self.log(f"传输结束：成功 {ok_count}/{nfiles} 个文件")
            if self.hooks:
                self.hooks.finished(ok_count == nfiles, f"{ok_count}/{nfiles} 个文件")
        except Exception as e:
            traceback.print_exc()
            self.log(f"[异常] {e}")
            if self.hooks:
                self.hooks.finished(False, str(e))


def probe_peer(host, port, pin="", timeout=PING_TIMEOUT):
    """连接测试：返回 (ok, 说明, 信息字典)。"""
    try:
        conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
        conn.request("GET", "/ping")
        resp = conn.getresponse()
        info = json.loads(resp.read().decode("utf-8") or "{}")
        conn.close()
    except Exception as e:
        return False, f"连不上（{e}）", {}
    if info.get("app") != APP_NAME:
        return False, "对方不是 FileChannel 服务", info
    if info.get("pin_required") and pin:
        try:
            conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
            conn.request("POST", "/offer", body=b'{"files":[]}', headers={
                "Content-Type": "application/json", "X-Pin": pin,
                "Content-Length": "13"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 403:
                return False, "对方要求口令，且当前口令不正确", info
        except Exception:
            pass
    elif info.get("pin_required") and not pin:
        return True, "已连接（注意：对方设置了口令，需填写后才能发送）", info
    return True, f"已连接：{info.get('name')}（{info.get('host')}）", info


# --------------------------------------------------------------------------
# Windows 拖放（WM_DROPFILES，纯 ctypes，不需要第三方包）
# --------------------------------------------------------------------------
WM_DROPFILES = 0x0233
GWLP_WNDPROC = -4
_IS_WIN = os.name == "nt"

if _IS_WIN:
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _LRESULT = ctypes.c_ssize_t
    _WNDPROC = ctypes.WINFUNCTYPE(_LRESULT, wintypes.HWND, ctypes.c_uint,
                                  ctypes.c_size_t, ctypes.c_ssize_t)

    _shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
    _shell32.DragAcceptFiles.restype = None
    _shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT,
                                        wintypes.LPWSTR, wintypes.UINT]
    _shell32.DragQueryFileW.restype = wintypes.UINT
    _shell32.DragFinish.argtypes = [wintypes.HANDLE]
    _shell32.DragFinish.restype = None
    _user32.CallWindowProcW.argtypes = [ctypes.c_void_p, wintypes.HWND, ctypes.c_uint,
                                        ctypes.c_size_t, ctypes.c_ssize_t]
    _user32.CallWindowProcW.restype = _LRESULT
    _user32.PostMessageW.argtypes = [wintypes.HWND, ctypes.c_uint,
                                     ctypes.c_size_t, ctypes.c_ssize_t]
    _user32.PostMessageW.restype = wintypes.BOOL

    if hasattr(_user32, "SetWindowLongPtrW"):
        _set_wndproc = _user32.SetWindowLongPtrW
        _set_wndproc.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        _set_wndproc.restype = ctypes.c_void_p
    else:                                    # 32 位 Python
        _set_wndproc = _user32.SetWindowLongW
        _set_wndproc.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        _set_wndproc.restype = ctypes.c_void_p


class DropTarget:
    """给若干窗口安装“接受拖放”的能力。"""

    def __init__(self, on_drop):
        self.on_drop = on_drop
        self._procs = {}          # hwnd -> (WNDPROC, old_proc)
        self._installed = set()

    def register_widget(self, widget):
        if not _IS_WIN:
            return
        try:
            self._install(int(widget.winfo_id()))
            parent = _user32.GetParent(int(widget.winfo_id()))
            if parent:
                self._install(int(parent))
        except Exception:
            traceback.print_exc()

    def _install(self, hwnd):
        if not hwnd or hwnd in self._installed:
            return
        try:
            _shell32.DragAcceptFiles(hwnd, True)
            proc = _WNDPROC(self._wndproc)
            old = _set_wndproc(hwnd, GWLP_WNDPROC, ctypes.cast(proc, ctypes.c_void_p))
            self._procs[hwnd] = (proc, old)
            self._installed.add(hwnd)
        except Exception:
            traceback.print_exc()

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_DROPFILES:
            paths = []
            try:
                n = _shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)
                for i in range(n):
                    buf = ctypes.create_unicode_buffer(32768)
                    if _shell32.DragQueryFileW(wparam, i, buf, 32768):
                        paths.append(buf.value)
            finally:
                try:
                    _shell32.DragFinish(wparam)
                except Exception:
                    pass
            if paths:
                try:
                    self.on_drop(paths)
                except Exception:
                    traceback.print_exc()
            return 0
        entry = self._procs.get(hwnd)
        old = entry[1] if entry else None
        return _user32.CallWindowProcW(old, hwnd, msg, wparam, lparam)


def simulate_drop(hwnd, paths):
    """测试用：给窗口投递一个 WM_DROPFILES 消息。"""
    if not _IS_WIN:
        return False
    import struct
    files = "".join(p + "\0" for p in paths) + "\0"
    data = files.encode("utf-16-le")
    header = struct.pack("<IiiII", 20, 0, 0, 0, 1)     # pFiles, pt, fNC, fWide
    buf = header + data
    GMEM_MOVEABLE = 0x0002
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = ctypes.c_void_p
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    h = _kernel32.GlobalAlloc(GMEM_MOVEABLE, len(buf))
    p = _kernel32.GlobalLock(h)
    ctypes.memmove(p, buf, len(buf))
    _kernel32.GlobalUnlock(h)
    return bool(_user32.PostMessageW(hwnd, WM_DROPFILES, h, 0))


# --------------------------------------------------------------------------
# 图形界面
# --------------------------------------------------------------------------
class GuiHooks:
    """服务器/发送线程 -> 界面的回调（都在后台线程里被调用）。"""

    def __init__(self, app):
        self.app = app

    def ask_offer(self, offer):
        ev = threading.Event()
        self.app.ui_queue.put(("offer", offer, ev))
        if not ev.wait(OFFER_COUNTDOWN + 60):
            return "timeout"
        return offer.decision or "timeout"

    def progress(self, offer, fname, done, total, final=False):
        self.app.ui_queue.put(("rx_progress", offer, fname, done, total, final))


class SendHooks:
    def __init__(self, app, rows):
        self.app = app
        self.rows = rows              # [tree item id]，与顶层拖入项一一对应

    def prepared(self, info):
        self.app.ui_queue.put(("tx_prepared", info))

    def progress(self, idx, name, sent, size):
        self.app.ui_queue.put(("tx_progress", idx, name, sent, size))

    def finished(self, ok, msg):
        self.app.ui_queue.put(("tx_finished", ok, msg))


class App:
    def __init__(self, config=None):
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog, simpledialog

        self.tk = tk
        self.ttk = ttk
        self.messagebox = messagebox
        self.filedialog = filedialog
        self.simpledialog = simpledialog
        self.config = config or Config()
        self.ui_queue = queue.Queue()
        self.root = tk.Tk()
        self.root.title(f"文件通道 FileChannel — {self.config['name']}")
        self.root.geometry("1000x780")
        self.root.minsize(860, 620)

        self.peers_found = {}          # (ip, port) -> name
        self.send_rows = []            # [tree item id]（发送列表，一个顶层项一行）
        self.recv_rows = {}
        self.sender = None
        self.drop_target = DropTarget(self.on_drop)
        self._build_ui()

        self.hooks = GuiHooks(self)
        self.server = ChannelServer(self.config, self.hooks, log=self.log)
        self.server.start()
        self.server.ready.wait(3)
        if self.server.error:
            self.log(f"[错误] 监听 {self.config['tcp_port']} 端口失败：{self.server.error}"
                     f"（可能已有一个副本在运行，或端口被占用）")
            self.messagebox.showwarning(
                "端口占用",
                f"无法监听 {self.config['tcp_port']} 端口：\n{self.server.error}\n\n"
                "如果本程序已经开着了，请不要再开第二个。")
        else:
            self.log(f"正在监听 0.0.0.0:{self.config['tcp_port']}（TCP）")

        self.discovery = Discovery(self.config, self.on_peer_found, log=self.log)
        self.discovery.start()

        self.root.after(150, self.poll)
        threading.Thread(target=self.status_loop, daemon=True).start()

    # ---------------- 界面 ----------------
    def _build_ui(self):
        tk, ttk = self.tk, self.ttk
        pad = {"padx": 6, "pady": 3}

        # --- 第 1 行：本机信息 ---
        f1 = ttk.LabelFrame(self.root, text="本机")
        f1.pack(fill="x", **pad)
        ttk.Label(f1, text="名称").grid(row=0, column=0, sticky="w", padx=4, pady=3)
        self.var_name = tk.StringVar(value=self.config["name"])
        ttk.Entry(f1, textvariable=self.var_name, width=16).grid(row=0, column=1, sticky="w")
        ttk.Button(f1, text="改名", width=6, command=self.on_rename).grid(row=0, column=2, padx=4)

        ttk.Label(f1, text="本机地址").grid(row=0, column=3, sticky="w", padx=(12, 4))
        self.var_ip = tk.StringVar()
        self.cmb_ip = ttk.Combobox(f1, textvariable=self.var_ip, width=34, state="readonly")
        self.cmb_ip.grid(row=0, column=4, sticky="w")
        ttk.Button(f1, text="复制地址", width=9,
                   command=self.on_copy_addr).grid(row=0, column=5, padx=4)
        ttk.Button(f1, text="刷新", width=6,
                   command=self.refresh_ips).grid(row=0, column=6)

        ttk.Label(f1, text="接收目录").grid(row=1, column=0, sticky="w", padx=4, pady=3)
        self.var_dir = tk.StringVar(value=self.config["receive_dir"])
        ttk.Entry(f1, textvariable=self.var_dir).grid(row=1, column=1, columnspan=4,
                                                      sticky="we", padx=4)
        ttk.Button(f1, text="更改", width=6,
                   command=self.on_change_dir).grid(row=1, column=5, padx=4)
        ttk.Button(f1, text="打开", width=6,
                   command=lambda: open_folder(self.config["receive_dir"])).grid(row=1, column=6)
        f1.columnconfigure(4, weight=1)
        self.refresh_ips()

        # --- 第 2 行：对方 ---
        f2 = ttk.LabelFrame(self.root, text="对方 / 连接")
        f2.pack(fill="x", **pad)
        ttk.Label(f2, text="发现").grid(row=0, column=0, sticky="w", padx=4)
        self.var_found = tk.StringVar()
        self.cmb_found = ttk.Combobox(f2, textvariable=self.var_found, width=28, state="readonly")
        self.cmb_found.grid(row=0, column=1, sticky="w")
        self.cmb_found.bind("<<ComboboxSelected>>", self.on_pick_found)

        ttk.Label(f2, text="地址").grid(row=0, column=2, sticky="e", padx=(12, 2))
        self.var_host = tk.StringVar(value=self.config["last_peer"] or "")
        ttk.Entry(f2, textvariable=self.var_host, width=18).grid(row=0, column=3, sticky="w")
        ttk.Label(f2, text="端口").grid(row=0, column=4, sticky="e", padx=(8, 2))
        self.var_port = tk.StringVar(value=str(self.config["tcp_port"]))
        ttk.Entry(f2, textvariable=self.var_port, width=7).grid(row=0, column=5, sticky="w")
        ttk.Label(f2, text="口令").grid(row=0, column=6, sticky="e", padx=(8, 2))
        self.var_pin = tk.StringVar(value="")
        ttk.Entry(f2, textvariable=self.var_pin, width=10, show="*").grid(row=0, column=7, sticky="w")
        ttk.Button(f2, text="测试连接", command=self.on_test).grid(row=0, column=8, padx=6)
        ttk.Button(f2, text="记住对方", command=self.on_save_peer).grid(row=0, column=9, padx=2)

        self.var_status = tk.StringVar(value="未连接")
        self.lbl_status = ttk.Label(f2, textvariable=self.var_status, foreground="#a00")
        self.lbl_status.grid(row=1, column=0, columnspan=10, sticky="w", padx=4, pady=(2, 4))

        ttk.Label(f2, text="常用").grid(row=2, column=0, sticky="w", padx=4)
        self.var_peer = tk.StringVar()
        self.cmb_peers = ttk.Combobox(f2, textvariable=self.var_peer, width=28, state="readonly")
        self.cmb_peers.grid(row=2, column=1, sticky="w", pady=(0, 4))
        self.cmb_peers.bind("<<ComboboxSelected>>", self.on_pick_peer)
        ttk.Button(f2, text="删除该记录", command=self.on_del_peer).grid(row=2, column=2, padx=4)
        ttk.Label(f2, text="（本机口令留空=不校验；在校园网等环境建议设置）").grid(
            row=2, column=3, columnspan=7, sticky="w")
        self.refresh_peers()

        # --- 第 3 行：拖放区 ---
        self.drop_label = tk.Label(
            self.root,
            text="把文件 / 文件夹拖到这里发送\n（也可以点击这里选择文件）",
            font=("Microsoft YaHei UI", 14), bg="#e8f2ff", fg="#1552a0",
            relief="ridge", bd=2, height=4, cursor="hand2")
        self.drop_label.pack(fill="x", padx=8, pady=6)
        self.drop_label.bind("<Button-1>", lambda e: self.on_choose_files())

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=8)
        ttk.Button(bar, text="选择文件…", command=self.on_choose_files).pack(side="left")
        ttk.Button(bar, text="选择文件夹…", command=self.on_choose_folder).pack(side="left", padx=6)
        ttk.Button(bar, text="清空列表", command=self.on_clear_lists).pack(side="right")

        # --- 第 4 行：两个列表 ---
        lists = ttk.Frame(self.root)
        lists.pack(fill="both", expand=True, padx=8, pady=4)
        cols = ("file", "size", "progress", "state")
        widths = (300, 90, 90, 220)

        ttk.Label(lists, text="发送").grid(row=0, column=0, sticky="w")
        self.tree_send = ttk.Treeview(lists, columns=cols, show="headings", height=6)
        for c, w, t in zip(cols, widths, ("文件", "大小", "进度", "状态")):
            self.tree_send.heading(c, text=t)
            self.tree_send.column(c, width=w, anchor="w")
        self.tree_send.grid(row=1, column=0, sticky="nsew")

        ttk.Label(lists, text="接收").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.tree_recv = ttk.Treeview(lists, columns=cols, show="headings", height=6)
        for c, w, t in zip(cols, widths, ("文件", "大小", "进度", "状态")):
            self.tree_recv.heading(c, text=t)
            self.tree_recv.column(c, width=w, anchor="w")
        self.tree_recv.grid(row=3, column=0, sticky="nsew")
        lists.columnconfigure(0, weight=1)
        lists.rowconfigure(1, weight=1)
        lists.rowconfigure(3, weight=1)

        # --- 第 5 行：日志 ---
        f5 = ttk.LabelFrame(self.root, text="日志")
        f5.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.txt_log = tk.Text(f5, height=7, wrap="none")
        sb = ttk.Scrollbar(f5, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        self.txt_log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        for w in (self.root, self.drop_label, lists, self.tree_send, self.tree_recv):
            self.drop_target.register_widget(w)

    # ---------------- 小功能 ----------------
    def log(self, msg):
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}\n"
        try:
            self.ui_queue.put(("log", line))
        except Exception:
            print(line, end="")

    def refresh_ips(self):
        self.ip_list = local_ipv4_list()
        vals = [f"{ip}:{self.config['tcp_port']}" for ip, _m in self.ip_list]
        self.cmb_ip["values"] = vals
        if vals:
            self.var_ip.set(vals[0])

    def refresh_peers(self):
        rows = self.config["peers"] or []
        vals = [f"{p.get('label') or p.get('host')}  ({p.get('host')}:{p.get('port')})"
                for p in rows]
        self.cmb_peers["values"] = vals

    def on_rename(self):
        name = (self.var_name.get() or "").strip()
        if name:
            self.config["name"] = name
            self.config.save()
            self.root.title(f"文件通道 FileChannel — {name}")
            self.log(f"本机名称改为：{name}")

    def on_copy_addr(self):
        val = self.var_ip.get()
        if val:
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            self.log(f"已复制本机地址：{val}（把它告诉对方）")

    def on_change_dir(self):
        d = self.filedialog.askdirectory(initialdir=self.config["receive_dir"])
        if d:
            self.config["receive_dir"] = d
            self.config.save()
            self.var_dir.set(d)

    def on_clear_lists(self):
        for t in (self.tree_send, self.tree_recv):
            for i in t.get_children():
                t.delete(i)
        self.send_rows = []
        self.recv_rows.clear()

    def on_pick_peer(self, _evt=None):
        sel = self.var_peer.get()
        for p in self.config["peers"] or []:
            label = f"{p.get('label') or p.get('host')}  ({p.get('host')}:{p.get('port')})"
            if label == sel:
                self.var_host.set(p.get("host", ""))
                self.var_port.set(str(p.get("port") or DEFAULT_TCP_PORT))
                self.var_pin.set(p.get("pin") or "")
                self.log(f"已选择常用对方：{p.get('label') or p.get('host')}")
                break

    def on_save_peer(self):
        host = (self.var_host.get() or "").strip()
        if not host:
            return
        label = self.simpledialog.askstring("保存对方", "给它起个名字：",
                                              initialvalue=host)
        if label is None:
            return
        entry = {"label": label or host, "host": host,
                 "port": int(self.var_port.get() or DEFAULT_TCP_PORT),
                 "pin": self.var_pin.get() or ""}
        peers = [p for p in (self.config["peers"] or [])
                 if not (p.get("host") == host and str(p.get("port")) == str(entry["port"]))]
        peers.append(entry)
        self.config["peers"] = peers
        self.config["last_peer"] = host
        self.config.save()
        self.refresh_peers()
        self.log(f"已记住对方：{entry['label']} ({entry['host']}:{entry['port']})")

    def on_del_peer(self):
        sel = self.var_peer.get()
        peers = []
        for p in (self.config["peers"] or []):
            label = f"{p.get('label') or p.get('host')}  ({p.get('host')}:{p.get('port')})"
            if label != sel:
                peers.append(p)
        self.config["peers"] = peers
        self.config.save()
        self.refresh_peers()
        self.var_peer.set("")

    def on_pick_found(self, _evt=None):
        sel = self.var_found.get()
        for (ip, port), name in self.peers_found.items():
            if sel.startswith(f"{name} ") or sel == f"{name} ({ip}:{port})":
                self.var_host.set(ip)
                self.var_port.set(str(port))
                self.log(f"已填入发现的设备：{name} {ip}:{port}")
                break

    def on_peer_found(self, name, ip, port):
        key = (ip, port)
        if key in self.peers_found:
            return
        self.peers_found[key] = name
        vals = [f"{n} ({i}:{p})" for (i, p), n in self.peers_found.items()]
        self.ui_queue.put(("found", vals))
        self.ui_queue.put(("log", f"[{time.strftime('%H:%M:%S')}] 发现设备：{name} {ip}:{port}\n"))

    # ---------------- 连接测试 ----------------
    def on_test(self):
        host = (self.var_host.get() or "").strip()
        port = int(self.var_port.get() or DEFAULT_TCP_PORT)
        if not host:
            self.messagebox.showwarning("提示", "请先填写对方地址")
            return
        self.var_status.set("正在测试…")
        self.lbl_status.configure(foreground="#a60")

        def work():
            ok, msg, _info = probe_peer(host, port, self.var_pin.get() or "")
            self.ui_queue.put(("status", ok, msg))
        threading.Thread(target=work, daemon=True).start()

    def status_loop(self):
        """后台每隔几秒戳一下对方，更新连接状态。"""
        last_ok = None
        while True:
            time.sleep(6)
            host = (self.var_host.get() or "").strip()
            if not host:
                continue
            try:
                port = int(self.var_port.get() or DEFAULT_TCP_PORT)
            except Exception:
                continue
            ok, msg, _info = probe_peer(host, port, self.var_pin.get() or "", timeout=3.0)
            if ok != last_ok:
                last_ok = ok
                self.ui_queue.put(("status", ok, msg if ok else f"未连接（{msg}）"))

    # ---------------- 拖放 / 选择文件 ----------------
    def on_drop(self, paths):
        self.log(f"拖入 {len(paths)} 项，准备发送…")
        self.start_send(paths)

    def on_choose_files(self):
        paths = self.filedialog.askopenfilenames(title="选择要发送的文件")
        if paths:
            self.start_send(list(paths))

    def on_choose_folder(self):
        d = self.filedialog.askdirectory(title="选择要发送的文件夹（会自动打包成 zip）")
        if d:
            self.start_send([d])

    def start_send(self, paths):
        host = (self.var_host.get() or "").strip()
        if not host:
            self.messagebox.showwarning(
                "还没有填对方地址",
                "请先在上面填写对方的地址和端口（对方打开本程序后，"
                "把它窗口里显示的“本机地址”填到这里），\n"
                "或者从“发现”下拉框里选择自动找到的设备。")
            return
        try:
            port = int(self.var_port.get() or DEFAULT_TCP_PORT)
        except Exception:
            self.messagebox.showwarning("提示", "端口必须是数字")
            return
        paths = [p for p in paths if os.path.exists(p)]
        if not paths:
            return
        self.config["last_peer"] = host
        self.config.save()

        # 建立界面行（一个顶层项一行；文件夹的真实大小等扫描完再填）
        row_ids = []
        for p in paths:
            name = os.path.basename(p.rstrip("\\/")) or p
            is_dir = os.path.isdir(p)
            try:
                size = os.path.getsize(p) if os.path.isfile(p) else 0
            except Exception:
                size = 0
            iid = self.tree_send.insert("", "end", values=(
                name,
                human_size(size) if size else ("文件夹" if is_dir else "—"),
                "0%",
                "扫描中…" if is_dir else "等待对方接受…"))
            row_ids.append(iid)
        self.send_rows = row_ids

        hooks = SendHooks(self, row_ids)
        self.sender = Sender(paths, host, port, pin=self.var_pin.get() or "",
                             my_name=self.config["name"], hooks=hooks, log=self.log)
        self.sender.start()

    # ---------------- 事件循环 ----------------
    def poll(self):
        try:
            while True:
                item = self.ui_queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self.txt_log.insert("end", item[1])
                    self.txt_log.see("end")
                elif kind == "found":
                    self.cmb_found["values"] = item[1]
                elif kind == "status":
                    ok, msg = item[1], item[2]
                    self.var_status.set(("● " if ok else "○ ") + msg)
                    self.lbl_status.configure(foreground="#080" if ok else "#a00")
                elif kind == "offer":
                    self.handle_offer(item[1], item[2])
                elif kind == "tx_prepared":
                    for i, (name, size, nfiles) in enumerate(item[1]):
                        if i >= len(self.send_rows):
                            break
                        iid = self.send_rows[i]
                        shown = human_size(size) if size else "0 B"
                        if nfiles != 1:
                            shown += f"（{nfiles} 个文件）"
                        self.tree_send.set(iid, "size", shown)
                        self.tree_send.set(iid, "state", "等待对方接受…")
                elif kind == "tx_progress":
                    _k, idx, _name, sent, size = item
                    if idx < len(self.send_rows):
                        iid = self.send_rows[idx]
                        pct = f"{sent * 100 // max(size, 1)}%"
                        self.tree_send.set(iid, "progress", pct)
                        self.tree_send.set(iid, "state", "发送中…")
                elif kind == "tx_finished":
                    ok, msg = item[1], item[2]
                    for iid in self.send_rows:
                        st = self.tree_send.set(iid, "state")
                        if st in ("等待对方接受…", "发送中…", "扫描中…"):
                            self.tree_send.set(iid, "state", "完成" if ok else f"失败：{msg}")
                            if ok:
                                self.tree_send.set(iid, "progress", "100%")
                elif kind == "rx_progress":
                    _k, offer, fname, done, total, final = item
                    key = f"{offer.id}:{fname}"
                    iid = self.recv_rows.get(key)
                    if iid is None:
                        iid = self.tree_recv.insert("", "end", values=(
                            fname, human_size(total), "0%", "接收中…"))
                        self.recv_rows[key] = iid
                    pct = f"{done * 100 // max(total, 1)}%"
                    self.tree_recv.set(iid, "progress", pct)
                    self.tree_recv.set(iid, "state",
                                       f"完成（{human_size(done)}）" if final else "接收中…")
                    if final:
                        self.recv_alert()
        except queue.Empty:
            pass
        except Exception:
            traceback.print_exc()
        self.root.after(150, self.poll)

    def recv_alert(self):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception:
            pass

    # ---------------- 收到请求：接受 / 拒绝 ----------------
    def handle_offer(self, offer, event):
        tk, ttk = self.tk, self.ttk
        self.recv_alert()
        dlg = tk.Toplevel(self.root)
        dlg.title("收到文件传输请求")
        dlg.transient(self.root)
        dlg.attributes("-topmost", True)
        dlg.resizable(False, False)
        dlg.grab_set()

        ttk.Label(dlg, text=f"【{offer.peer_name}】 想给你发送文件",
                  font=("Microsoft YaHei UI", 12, "bold")).pack(padx=16, pady=(14, 4))
        n_files = sum(1 for f in offer.files if not f.get("dir"))
        ttk.Label(dlg, text=f"共 {n_files} 个文件，合计 {human_size(offer.total_size)}"
                  ).pack(padx=16)
        rows_n = min(12, max(3, len(offer.files)))
        tree = ttk.Treeview(dlg, columns=("f", "s"), show="headings", height=rows_n)
        tree.heading("f", text="文件（相对路径）")
        tree.heading("s", text="大小")
        tree.column("f", width=380)
        tree.column("s", width=100, anchor="e")
        for f in offer.files:
            label = f.get("rel") or f.get("name") or ""
            if f.get("dir"):
                tree.insert("", "end", values=(label + "　（空文件夹）", "—"))
            else:
                tree.insert("", "end", values=(label, human_size(int(f.get("size") or 0))))
        tree.pack(padx=16, pady=8, fill="x")

        var_auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(dlg, text="以后自动接受来自该主机的文件",
                        variable=var_auto).pack(anchor="w", padx=16)

        var_cd = tk.StringVar()
        ttk.Label(dlg, textvariable=var_cd, foreground="#a60").pack(pady=(6, 0))

        btns = ttk.Frame(dlg)
        btns.pack(padx=16, pady=(6, 14), fill="x")

        state = {"left": OFFER_COUNTDOWN}

        def close(decision):
            offer.decide(decision)
            dlg.grab_release()
            dlg.destroy()
            event.set()

        def accept():
            if var_auto.get():
                auto = list(self.config["auto_accept"] or [])
                if offer.sender not in auto:
                    auto.append(offer.sender)
                    self.config["auto_accept"] = auto
                    self.config.save()
            stamp = time.strftime("%Y%m%d_%H%M%S")
            folder = f"{safe_name(offer.sender)}_{stamp}"
            offer.dest_dir = os.path.join(self.config["receive_dir"], folder)
            close("accept")

        def reject():
            close("reject")

        ttk.Button(btns, text="接受", command=accept).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(btns, text="拒绝", command=reject).pack(side="left", expand=True, fill="x", padx=4)

        def tick():
            if not dlg.winfo_exists():
                return
            state["left"] -= 1
            var_cd.set(f"{state['left']} 秒后自动拒绝")
            if state["left"] <= 0:
                close("timeout")
                return
            dlg.after(1000, tick)

        var_cd.set(f"{state['left']} 秒后自动拒绝")
        dlg.after(1000, tick)
        dlg.update_idletasks()
        # 居中并置前
        try:
            x = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_width()) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - dlg.winfo_height()) // 3
            dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
            dlg.deiconify()
            dlg.lift()
            dlg.focus_force()
        except Exception:
            pass
        self.root.wait_window(dlg)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def on_close(self):
        try:
            self.server.stop()
            self.discovery.stop()
        except Exception:
            pass
        self.root.destroy()


# --------------------------------------------------------------------------
# 命令行模式
# --------------------------------------------------------------------------
class ConsoleHooks:
    def __init__(self, auto_accept=False, timeout=OFFER_COUNTDOWN):
        self.auto_accept = auto_accept
        self.timeout = timeout

    def ask_offer(self, offer):
        print(f"\n*** 【{offer.sender}】想发送 {len(offer.files)} 个文件 "
              f"({human_size(offer.total_size)})：")
        for f in offer.files:
            print(f"      - {f.get('name')}  ({human_size(int(f.get('size') or 0))})")
        if self.auto_accept:
            print("    （自动接受）")
            return "accept"
        try:
            ans = input("    接受吗？[Y/n] ").strip().lower()
        except Exception:
            return "reject"
        return "reject" if ans in ("n", "no") else "accept"

    def progress(self, offer, fname, done, total, final=False):
        if final:
            print(f"    [完成] {fname} ({human_size(done)})")


class CliSendHooks:
    def __init__(self):
        self.last = {}

    def progress(self, idx, name, sent, size):
        pct = sent * 100 // max(size, 1)
        if self.last.get(idx) != pct // 5:
            self.last[idx] = pct // 5
            print(f"\r  {name}: {pct}% ", end="", flush=True)

    def finished(self, ok, msg):
        print(f"\n  结果：{'成功' if ok else '失败'}（{msg}）")


def cli_serve(args):
    cfg = Config()
    if args.name:
        cfg["name"] = args.name
    if args.port:
        cfg["tcp_port"] = args.port
    if args.pin is not None:
        cfg["pin"] = args.pin
    if args.dir:
        cfg["receive_dir"] = args.dir
    print(f"{APP_NAME} 命令行接收模式")
    print(f"  本机名称：{cfg['name']}")
    print(f"  接收目录：{cfg['receive_dir']}")
    print(f"  监听端口：{cfg['tcp_port']}（口令：{'已设置' if cfg['pin'] else '未设置'}）")
    for ip, _m in local_ipv4_list():
        print(f"  本机地址：{ip}:{cfg['tcp_port']}")
    hooks = ConsoleHooks(auto_accept=args.auto_accept)
    srv = ChannelServer(cfg, hooks, port=cfg["tcp_port"],
                        log=lambda m: print(f"  {m}", flush=True))
    srv.start()
    srv.ready.wait(3)
    if srv.error:
        print(f"  监听失败：{srv.error}")
        return 1
    print("  等待对方连接…（Ctrl+C 退出）")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  退出")
    srv.stop()
    return 0


def cli_send(args):
    cfg = Config()
    target = args.to
    if ":" in target:
        host, port = target.rsplit(":", 1)
        port = int(port)
    else:
        host, port = target, DEFAULT_TCP_PORT
    name = args.name or cfg["name"]
    print(f"{APP_NAME} 命令行发送模式：{', '.join(args.paths)} -> {host}:{port}")
    s = Sender(args.paths, host, port, pin=args.pin or "", my_name=name,
               hooks=CliSendHooks(), log=lambda m: print(f"  {m}", flush=True))
    s.start()
    s.join()
    return 0


def cli_drop_selftest(args):
    """自动化测试：启动界面，合成一次拖放，检查是否进入发送列表。"""
    out = args.selftest_drop
    cfg = Config()
    app = App(cfg)
    # 自检时不需要真的发出去，只要能进“发送列表”即可
    app.var_host.set("127.0.0.1")
    app.var_port.set("9")
    result = {"paths": args.paths, "rows": [], "hwnd": None}

    def do_drop():
        try:
            hwnd = int(app.drop_label.winfo_id())
            result["hwnd"] = hwnd
            ok = simulate_drop(hwnd, args.paths)
            result["posted"] = ok
        except Exception as e:
            import traceback
            result["error"] = repr(e)
            result["traceback"] = traceback.format_exc()

    def check():
        try:
            for iid in app.tree_send.get_children():
                result["rows"].append(app.tree_send.item(iid, "values"))
        finally:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            app.on_close()

    app.root.after(1200, do_drop)
    app.root.after(3200, check)
    app.run()
    print(json.dumps(result, ensure_ascii=False))
    return 0


def attach_console():
    """打包成 --windowed exe 后，命令行模式仍能把输出显示在父控制台里。"""
    if os.name != "nt":
        return
    if not getattr(sys, "frozen", False):
        return
    try:
        if ctypes.windll.kernel32.AttachConsole(-1):     # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
    except Exception:
        pass


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description=f"{APP_NAME} 文件通道（{APP_VERSION}）")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    p.add_argument("--serve", action="store_true", help="命令行接收模式")
    p.add_argument("--send", nargs="+", metavar="PATH", help="命令行发送文件/文件夹")
    p.add_argument("--to", metavar="HOST[:PORT]", help="对方地址（配合 --send）")
    p.add_argument("--pin", default=None, help="口令")
    p.add_argument("--port", type=int, help="监听端口（配合 --serve）")
    p.add_argument("--dir", help="接收目录（配合 --serve）")
    p.add_argument("--name", help="本机显示名称")
    p.add_argument("--auto-accept", action="store_true", help="命令行模式下自动接受")
    p.add_argument("--selftest-drop", metavar="OUTJSON", help=argparse.SUPPRESS)
    args, extra = p.parse_known_args(argv)

    if args.serve or (args.send and args.to) or args.selftest_drop:
        attach_console()
    if args.selftest_drop:
        args.paths = extra
        return cli_drop_selftest(args)
    if args.serve:
        return cli_serve(args)
    if args.send and args.to:
        args.paths = args.send
        return cli_send(args)
    if args.send and not args.to:
        print("错误：--send 需要配合 --to HOST[:PORT]")
        return 2

    cfg = Config()
    if args.port:
        cfg["tcp_port"] = args.port
    if args.pin is not None:
        cfg["pin"] = args.pin
    if args.name:
        cfg["name"] = args.name
    app = App(cfg)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
