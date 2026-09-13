# -*- coding: utf-8 -*-
"""FileChannel 自动化测试（不需要人工点击）

运行：  python test_filechannel.py
"""
import hashlib
import io
import json
import os
import shutil
import socket
import sys
import threading
import time
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import FileChannel as fc  # noqa: E402

BASE_PORT = 18765
BASE_UDP = 18766
FAILED = []


def check(name, cond, extra=""):
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (f"  {extra}" if extra else ""))
    if not cond:
        FAILED.append(name)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class AutoHooks:
    def __init__(self, decision="accept", logs=None):
        self.decision = decision
        self.offers = []
        self.logs = logs if logs is not None else []

    def ask_offer(self, offer):
        self.offers.append(offer)
        return self.decision

    def progress(self, offer, fname, done, total, final=False):
        pass


class SendHooks:
    def __init__(self, logs=None):
        self.done = threading.Event()
        self.ok = None
        self.msg = ""
        self.logs = logs if logs is not None else []

    def progress(self, idx, name, sent, size):
        pass

    def finished(self, ok, msg):
        self.ok, self.msg = ok, msg
        self.done.set()


class Ctx:
    """一次测试的上下文：独立端口、目录、日志。"""

    def __init__(self, tmp, idx, pin=""):
        self.idx = idx
        self.port = BASE_PORT + idx
        self.udp = BASE_UDP + idx
        self.logs = []
        self.cfg = fc.Config(path=os.path.join(tmp, f"cfg{idx}.json"))
        self.cfg["name"] = "测试机"
        self.cfg["tcp_port"] = self.port
        self.cfg["udp_port"] = self.udp
        self.cfg["pin"] = pin
        self.cfg["receive_dir"] = os.path.join(tmp, f"recv{idx}")
        os.makedirs(self.cfg["receive_dir"], exist_ok=True)
        self.srv = None

    def log(self, msg):
        self.logs.append(str(msg))
        print(f"      · {msg}")

    def start(self, hooks):
        self.srv = fc.ChannelServer(self.cfg, hooks, port=self.port, log=self.log)
        self.srv.start()
        self.srv.ready.wait(5)
        assert self.srv.error is None, f"服务启动失败: {self.srv.error}"
        return self.srv

    def stop(self):
        try:
            if self.srv:
                self.srv.stop()
        except Exception:
            pass
        time.sleep(0.2)

    def wait_files(self, n, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            got = []
            for root, _d, files in os.walk(self.cfg["receive_dir"]):
                for f in files:
                    got.append(os.path.join(root, f))
            if len(got) >= n:
                return sorted(got)
            time.sleep(0.2)
        return []


def t_happy_path(tmp):
    print("1) 正常发送（一个请求多个文件 + 大文件）")
    ctx = Ctx(tmp, 0)
    before = len(FAILED)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        src = os.path.join(tmp, "src1")
        os.makedirs(src, exist_ok=True)
        files = []
        for i, size in enumerate((5 << 20, 1024, 3 << 20)):
            p = os.path.join(src, f"file{i}.bin")
            with open(p, "wb") as f:
                f.write(os.urandom(size))
            files.append(p)
        sh = SendHooks(ctx.logs)
        fc.Sender(files, "127.0.0.1", ctx.port, my_name="发送机", hooks=sh,
                  log=ctx.log, temp_dir=tmp).start()
        ok = sh.done.wait(120)
        check("发送完成", ok and sh.ok is True, sh.msg)
        got = ctx.wait_files(3)
        check("接收 3 个文件", len(got) == 3, str(len(got)))
        for p in files:
            name = os.path.basename(p)
            match = [g for g in got if os.path.basename(g) == name]
            same = bool(match) and sha(match[0]) == sha(p)
            check(f"内容一致 {name} ({os.path.getsize(p)} B)", same,
                  "" if same else f"收到 {os.path.getsize(match[0]) if match else '无'}")
    finally:
        ctx.stop()
        if len(FAILED) > before:
            print("      相关日志：" + " | ".join(ctx.logs[-8:]))


def t_reject(tmp):
    print("2) 对方拒绝")
    ctx = Ctx(tmp, 1)
    ctx.start(AutoHooks("reject", ctx.logs))
    try:
        p = os.path.join(tmp, "r.bin")
        with open(p, "wb") as f:
            f.write(b"x" * 1000)
        sh = SendHooks()
        fc.Sender([p], "127.0.0.1", ctx.port, hooks=sh, log=ctx.log, temp_dir=tmp).start()
        check("发送线程结束", sh.done.wait(60))
        check("结果=失败", sh.ok is False, sh.msg)
        check("没有落盘", not ctx.wait_files(1, timeout=2))
    finally:
        ctx.stop()


def t_pin(tmp):
    print("3) 口令校验")
    ctx = Ctx(tmp, 2, pin="secret")
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        p = os.path.join(tmp, "p.bin")
        with open(p, "wb") as f:
            f.write(b"y" * 4096)
        sh = SendHooks()
        fc.Sender([p], "127.0.0.1", ctx.port, pin="wrong", hooks=sh,
                  log=ctx.log, temp_dir=tmp).start()
        check("口令错误被拒", sh.done.wait(60) and sh.ok is False, sh.msg)
        ok, msg, _info = fc.probe_peer("127.0.0.1", ctx.port, pin="wrong")
        check("probe 检测出口令不符", ok is False, msg)
        sh2 = SendHooks()
        fc.Sender([p], "127.0.0.1", ctx.port, pin="secret", hooks=sh2,
                  log=ctx.log, temp_dir=tmp).start()
        check("口令正确可发送", sh2.done.wait(60) and sh2.ok is True, sh2.msg)
        check("文件已落盘并完整", any(sha(f) == sha(p) for f in ctx.wait_files(1)))
    finally:
        ctx.stop()


def t_sanitize(tmp):
    print("4) 恶意文件名不会跑出接收目录")
    ctx = Ctx(tmp, 3)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        conn = fc.http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=10)
        body = json.dumps({"from": "attacker",
                           "files": [{"name": "../../evil.txt", "size": 5}]}).encode()
        conn.request("POST", "/offer", body=body,
                     headers={"Content-Length": str(len(body)),
                              "Content-Type": "application/json"})
        ans = json.loads(conn.getresponse().read().decode())
        check("请求被接受（测试用）", ans.get("accept") is True, str(ans))
        token = ans.get("token")
        conn.close()
        conn = fc.http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=10)
        conn.putrequest("POST", "/upload")
        conn.putheader("X-Token", token)
        conn.putheader("X-File-Name", fc.urllib.parse.quote("../../evil.txt"))
        conn.putheader("Content-Length", "5")
        conn.endheaders()
        conn.send(b"hello")
        r = json.loads(conn.getresponse().read().decode())
        check("上传成功", r.get("ok") is True, str(r))
        saved = r.get("path", "")
        rp = os.path.abspath(ctx.cfg["receive_dir"])
        sp = os.path.abspath(saved)
        check("保存在接收目录内", sp == rp or sp.startswith(rp + os.sep), saved)
        check("文件名已净化", os.path.basename(saved) == "evil.txt", os.path.basename(saved))
    finally:
        ctx.stop()


def t_folder_zip(tmp):
    print("5) 文件夹自动打包")
    src = os.path.join(tmp, "folder1")
    os.makedirs(os.path.join(src, "sub"), exist_ok=True)
    with open(os.path.join(src, "a.txt"), "w", encoding="utf-8") as f:
        f.write("hello")
    with open(os.path.join(src, "sub", "b.txt"), "w", encoding="utf-8") as f:
        f.write("world")
    ctx = Ctx(tmp, 4)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        sh = SendHooks()
        fc.Sender([src], "127.0.0.1", ctx.port, hooks=sh, log=ctx.log,
                  temp_dir=tmp).start()
        check("打包并发送完成", sh.done.wait(60) and sh.ok is True, sh.msg)
        got = ctx.wait_files(1)
        check("收到 zip", bool(got) and got[0].endswith(".zip"), str(got))
        if got:
            import zipfile
            with zipfile.ZipFile(got[0]) as z:
                names = z.namelist()
            check("zip 内容正确", any(n.endswith("a.txt") for n in names) and
                  any(n.endswith("b.txt") for n in names), str(names))
    finally:
        ctx.stop()


def t_bad_token(tmp):
    print("6) 没有许可（token）不能上传")
    ctx = Ctx(tmp, 5)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        conn = fc.http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=10)
        conn.putrequest("POST", "/upload")
        conn.putheader("X-Token", "bogus")
        conn.putheader("X-File-Name", "x.txt")
        conn.putheader("Content-Length", "3")
        conn.endheaders()
        conn.send(b"abc")
        resp = conn.getresponse()
        check("被拒绝(403)", resp.status == 403, str(resp.status))
    finally:
        ctx.stop()


def t_incomplete(tmp):
    print("7) 传输不完整会被发现")
    ctx = Ctx(tmp, 6)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        conn = fc.http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=10)
        body = json.dumps({"from": "t", "files": [{"name": "half.bin", "size": 100}]}).encode()
        conn.request("POST", "/offer", body=body, headers={"Content-Length": str(len(body))})
        token = json.loads(conn.getresponse().read().decode())["token"]
        conn.close()
        conn = fc.http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=10)
        conn.putrequest("POST", "/upload")
        conn.putheader("X-Token", token)
        conn.putheader("X-File-Name", "half.bin")
        conn.putheader("Content-Length", "100")
        conn.endheaders()
        conn.send(b"z" * 40)
        conn.sock.shutdown(socket.SHUT_WR)
        r = json.loads(conn.getresponse().read().decode())
        check("返回失败", r.get("ok") is False, str(r))
    finally:
        ctx.stop()


def t_probe_and_discovery(tmp):
    print("8) 连接测试 + 自动发现")
    ctx = Ctx(tmp, 7)
    ctx.start(AutoHooks("accept", ctx.logs))
    found = []
    disc = fc.Discovery(ctx.cfg, lambda n, ip, p: found.append((n, ip, p)), log=ctx.log)
    disc.start()
    try:
        ok, msg, info = fc.probe_peer("127.0.0.1", ctx.port)
        check("probe 成功", ok is True, msg)
        check("probe 认出本程序", info.get("app") == fc.APP_NAME, str(info.get("app")))
        check("probe 报告无需口令", info.get("pin_required") is False, str(info))

        ips = [ip for ip, _m in fc.local_ipv4_list()
               if not ip.startswith(("127.", "169.254."))]
        lan = ips[0] if ips else "127.0.0.1"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        payload = json.dumps({"app": fc.APP_NAME, "name": "笔记本", "host": "LAPTOP-X",
                              "port": 9999}).encode()
        for _ in range(4):
            s.sendto(payload, (lan, ctx.udp))
            time.sleep(0.3)
        s.close()
        time.sleep(1.2)
        check("发现对方", any(f[0] == "笔记本" for f in found), f"lan={lan} found={found}")
    finally:
        disc.stop()
        ctx.stop()


def t_cli(tmp):
    print("9) 命令行 --send 走通")
    ctx = Ctx(tmp, 8)
    ctx.start(AutoHooks("accept", ctx.logs))
    try:
        p = os.path.join(tmp, "cli.bin")
        with open(p, "wb") as f:
            f.write(b"cli" * 1000)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fc.main(["--send", p, "--to", f"127.0.0.1:{ctx.port}", "--name", "CLI"])
        check("cli 返回 0", rc == 0, f"rc={rc}")
        got = ctx.wait_files(1)
        check("文件已送达且完整", bool(got) and sha(got[0]) == sha(p), str(got))
    finally:
        ctx.stop()


def t_offer_timeout(tmp):
    print("10) 对方不响应时会超时（不会永久卡住）")
    ctx = Ctx(tmp, 9)
    ctx.start(AutoHooks("timeout", ctx.logs))
    try:
        p = os.path.join(tmp, "to.bin")
        with open(p, "wb") as f:
            f.write(b"t" * 100)
        sh = SendHooks()
        old = fc.OFFER_WAIT_SENDER
        fc.OFFER_WAIT_SENDER = 3
        try:
            fc.Sender([p], "127.0.0.1", ctx.port, hooks=sh, log=ctx.log,
                      temp_dir=tmp).start()
            check("拿到结果", sh.done.wait(30))
            check("结果是失败/超时", sh.ok is False, sh.msg)
        finally:
            fc.OFFER_WAIT_SENDER = old
    finally:
        ctx.stop()


def main():
    base = os.environ.get("FC_TEST_DIR") or os.path.join(HERE, "_test_run")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base, exist_ok=True)
    print(f"测试目录：{base}\n")
    for fn in (t_happy_path, t_reject, t_pin, t_sanitize, t_folder_zip, t_bad_token,
               t_incomplete, t_probe_and_discovery, t_cli, t_offer_timeout):
        try:
            fn(base)
        except Exception as e:
            import traceback
            traceback.print_exc()
            FAILED.append(f"{fn.__name__} 异常: {e}")
        print()
    time.sleep(0.5)
    print("=" * 64)
    if FAILED:
        print(f"失败 {len(FAILED)} 项：")
        for f in FAILED:
            print(f"   - {f}")
        return 1
    print("全部通过 ✅")
    shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
