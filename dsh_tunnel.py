#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSH 云服务一键隧道
==================
在本地建立 SSH 本地端口转发隧道，把云端服务器上仅监听 127.0.0.1:3080 的
DSH (DeepSeek Harness) 服务映射到本机，实现一键访问。

用法：
    pip install -r requirements.txt
    python dsh_tunnel.py

依赖：
    paramiko   （唯一第三方库，SSH 连接与端口转发）
    tkinter    （Python 自带 GUI 库）
"""

import json
import os
import queue
import socket
import select
import shutil
import sys
import threading
import webbrowser
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

try:
    import paramiko
except ImportError:
    paramiko = None

# 让界面在高 DPI 屏幕下更清晰（仅 Windows）
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass


if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
KEYS_DIR = os.path.join(APP_DIR, "keys")

DEFAULT_PROFILE = {
    "host": "",
    "ssh_port": 22,
    "username": "root",
    "key_path": "",
    "password": "",
    "passphrase": "",
    "remember_passphrase": False,
    "local_host": "127.0.0.1",
    "local_port": 3080,
    "remote_host": "127.0.0.1",
    "remote_port": 3080,
}


# ---------------------------------------------------------------- 配置读写

def load_config():
    """读取配置，返回 {"active_profile": 名称, "profiles": {名称: 配置}}。"""
    data = None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        pass
    except Exception as e:
        print("读取配置失败:", e)

    # 新版：多配置预设
    if isinstance(data, dict) and isinstance(data.get("profiles"), dict) and data["profiles"]:
        profiles = {}
        for name, p in data["profiles"].items():
            merged = dict(DEFAULT_PROFILE)
            if isinstance(p, dict):
                merged.update(p)
            profiles[name] = merged
        active = data.get("active_profile")
        if active not in profiles:
            active = next(iter(profiles))
        return {"active_profile": active, "profiles": profiles}

    # 旧版单配置：迁移为“默认”预设
    if isinstance(data, dict):
        merged = dict(DEFAULT_PROFILE)
        merged.update(data)
        return {"active_profile": "默认", "profiles": {"默认": merged}}

    return {"active_profile": "默认", "profiles": {"默认": dict(DEFAULT_PROFILE)}}


def save_config(cfg):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def resolve_key_path(key_path):
    """把相对路径解析为绝对路径（相对应用目录）。"""
    if not key_path:
        return ""
    if os.path.isabs(key_path):
        return key_path
    return os.path.normpath(os.path.join(APP_DIR, key_path))


def files_equal(a, b):
    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            return fa.read() == fb.read()
    except OSError:
        return False


# ---------------------------------------------------------------- 私钥加载

def load_private_key(path, passphrase=""):
    """自动识别密钥类型并加载（支持受口令保护的私钥）。"""
    password = passphrase if passphrase else None
    key_classes = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
    dss = getattr(paramiko, "DSSKey", None)   # paramiko 5.0 起移除了 DSA
    if dss is not None:
        key_classes.append(dss)
    last_errors = []
    for cls in key_classes:
        try:
            return cls.from_private_key_file(path, password=password)
        except paramiko.PasswordRequiredException:
            raise paramiko.SSHException("该私钥受口令保护，请填写正确的“私钥口令”。")
        except paramiko.SSHException as e:
            last_errors.append(str(e))
        except Exception as e:
            last_errors.append(str(e))
    detail = last_errors[-1] if last_errors else "未知错误"
    raise paramiko.SSHException("无法解析私钥文件：%s" % detail)


# ---------------------------------------------------------------- SSH 隧道

class SSHTunnel:
    """封装 SSH 本地端口转发隧道（等价于 ssh -N -L 本地端口:远程地址:远程端口）。"""

    def __init__(self, cfg, on_status=None, on_log=None):
        self.cfg = cfg
        self.on_status = on_status
        self.on_log = on_log
        self._stop = threading.Event()
        self._client = None
        self._transport = None
        self._listener = None
        self._thread = None
        self._started = False

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _set_status(self, msg):
        if self.on_status:
            self.on_status(msg)

    def connect(self):
        """建立 SSH 连接（阻塞，应在工作线程调用）。"""
        host = (self.cfg.get("host") or "").strip()
        port = int(self.cfg.get("ssh_port") or 22)
        username = (self.cfg.get("username") or "").strip()
        key_path = resolve_key_path(self.cfg.get("key_path", ""))
        password = self.cfg.get("password") or None
        passphrase = self.cfg.get("passphrase") or ""

        if not host:
            raise ValueError("请填写服务器地址。")
        if not username:
            raise ValueError("请填写用户名。")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        if key_path:
            if not os.path.exists(key_path):
                raise ValueError("私钥文件不存在：%s" % key_path)
            pkey = load_private_key(key_path, passphrase)

        client.connect(
            hostname=host,
            port=port,
            username=username,
            pkey=pkey,
            password=password,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        transport.set_keepalive(30)
        self._client = client
        self._transport = transport
        return transport

    def start(self):
        if self._thread and self._thread.is_alive():
            raise RuntimeError("隧道已经在运行。")
        self._stop.clear()

        # 1) 建立 SSH 连接
        self.connect()
        self._log("SSH 连接已建立：%s@%s:%s"
                  % (self.cfg.get("username"), self.cfg.get("host"),
                     self.cfg.get("ssh_port")))

        # 2) 本地监听端口
        local_host = self.cfg.get("local_host") or "127.0.0.1"
        local_port = int(self.cfg.get("local_port") or 3080)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((local_host, local_port))
        except OSError as e:
            self.disconnect()
            raise RuntimeError("本地端口 %s 已被占用，无法监听：%s" % (local_port, e))
        listener.listen(64)
        listener.settimeout(0.5)
        self._listener = listener

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self._started = True
        self._set_status("已连接（转发 %s:%s -> %s:%s）"
                         % (local_host, local_port,
                            self.cfg.get("remote_host"), self.cfg.get("remote_port")))
        self._log("隧道已启动：本机 %s:%s  ->  远端 %s:%s"
                  % (local_host, local_port,
                     self.cfg.get("remote_host"), self.cfg.get("remote_port")))

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._forward, args=(conn, addr), daemon=True)
            t.start()

    def _forward(self, conn, addr):
        dest = (self.cfg.get("remote_host") or "127.0.0.1",
                int(self.cfg.get("remote_port") or 3080))
        try:
            channel = self._transport.open_channel("direct-tcpip", dest, addr)
        except Exception as e:
            self._log("转发通道建立失败（%s）：%s" % (addr[0], e))
            try:
                conn.close()
            except Exception:
                pass
            return
        self._log("新连接：%s:%s -> %s:%s"
                  % (addr[0], addr[1], dest[0], dest[1]))
        try:
            while not self._stop.is_set():
                try:
                    r, _, _ = select.select([conn, channel], [], [], 0.5)
                except (OSError, ValueError):
                    break
                if not r:
                    continue
                if conn in r:
                    data = conn.recv(65536)
                    if not data:
                        break
                    channel.sendall(data)
                if channel in r:
                    data = channel.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
        except Exception as e:
            self._log("转发连接结束：%s" % e)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            try:
                channel.close()
            except Exception:
                pass

    def disconnect(self):
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._transport = None
        self._client = None

    def stop(self):
        was = self._started
        self._started = False
        self._stop.set()
        if self._listener:
            try:
                self._listener.close()
            except Exception:
                pass
            self._listener = None
        self.disconnect()
        self._thread = None
        self._set_status("未连接")
        if was:
            self._log("隧道已停止。")

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())


# ---------------------------------------------------------------- 界面

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("DSH 云服务一键隧道")
        self.root.geometry("680x720")
        self.root.minsize(640, 660)

        self.cfg = load_config()
        self.active_profile = self.cfg["active_profile"]
        self.tunnel = None
        self._connecting = False
        self._q = queue.Queue()

        self._build_vars()
        self._build_ui()
        self._load_to_ui()
        self._sync_buttons()
        self._on_log("欢迎使用 DSH 云服务一键隧道。")
        if paramiko is None:
            self._on_log("警告：未安装 paramiko，请先运行 pip install paramiko。")

        self.root.after(80, self._poll_queue)

    # ---- 变量 ----
    def _build_vars(self):
        self.var_host = tk.StringVar()
        self.var_ssh_port = tk.StringVar()
        self.var_username = tk.StringVar()
        self.var_key_path = tk.StringVar()
        self.var_passphrase = tk.StringVar()
        self.var_remember_pass = tk.BooleanVar()
        self.var_password = tk.StringVar()
        self.var_local_port = tk.StringVar()
        self.var_remote_host = tk.StringVar()
        self.var_remote_port = tk.StringVar()
        self.var_profile = tk.StringVar()
        self.var_status = tk.StringVar(value="未连接")

    # ---- 构建界面 ----
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        # 配置预设（可保存多台服务器，切换无需重填）
        prof = ttk.LabelFrame(main, text="配置预设（可保存多台服务器，切换无需重填）", padding=10)
        prof.pack(fill="x", pady=(0, 8))
        prof.columnconfigure(1, weight=1)
        ttk.Label(prof, text="当前配置").grid(row=0, column=0, sticky="w", **pad)
        self.profile_combo = ttk.Combobox(prof, textvariable=self.var_profile, state="readonly", width=24)
        self.profile_combo.grid(row=0, column=1, sticky="ew", **pad)
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)
        self.btn_new_profile = ttk.Button(prof, text="新建", command=self.add_profile)
        self.btn_new_profile.grid(row=0, column=2, sticky="e", **pad)
        self.btn_rename_profile = ttk.Button(prof, text="重命名", command=self.rename_profile)
        self.btn_rename_profile.grid(row=0, column=3, sticky="e", **pad)
        self.btn_del_profile = ttk.Button(prof, text="删除", command=self.delete_profile)
        self.btn_del_profile.grid(row=0, column=4, sticky="e", **pad)

        # 服务器连接
        conn = ttk.LabelFrame(main, text="服务器连接", padding=10)
        conn.pack(fill="x", pady=(0, 8))
        conn.columnconfigure(1, weight=1)

        ttk.Label(conn, text="服务器地址").grid(row=0, column=0, sticky="w", **pad)
        self._entry(conn, self.var_host).grid(row=0, column=1, columnspan=3, sticky="ew", **pad)

        ttk.Label(conn, text="SSH 端口").grid(row=1, column=0, sticky="w", **pad)
        self._entry(conn, self.var_ssh_port, width=8).grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(conn, text="用户名").grid(row=2, column=0, sticky="w", **pad)
        self._entry(conn, self.var_username).grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(conn, text="SSH 私钥").grid(row=3, column=0, sticky="w", **pad)
        self._entry(conn, self.var_key_path).grid(row=3, column=1, columnspan=2, sticky="ew", **pad)
        self.btn_key = ttk.Button(conn, text="选择并保存私钥", command=self.choose_key)
        self.btn_key.grid(row=3, column=3, sticky="e", **pad)

        ttk.Label(conn, text="私钥口令").grid(row=4, column=0, sticky="w", **pad)
        self._entry(conn, self.var_passphrase, show="*").grid(row=4, column=1, sticky="ew", **pad)
        ttk.Checkbutton(conn, text="记住口令", variable=self.var_remember_pass).grid(
            row=4, column=2, sticky="w", **pad)

        ttk.Label(conn, text="SSH 密码(可选)").grid(row=5, column=0, sticky="w", **pad)
        self._entry(conn, self.var_password, show="*").grid(row=5, column=1, sticky="ew", **pad)

        # 端口转发
        fwd = ttk.LabelFrame(main, text="端口转发（云端 DSH 服务 -> 本机）", padding=10)
        fwd.pack(fill="x", pady=(0, 8))
        fwd.columnconfigure(1, weight=1)

        ttk.Label(fwd, text="本地端口").grid(row=0, column=0, sticky="w", **pad)
        self._entry(fwd, self.var_local_port, width=8).grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(fwd, text="本机浏览器访问 http://127.0.0.1:此端口").grid(
            row=0, column=2, sticky="w", **pad)

        ttk.Label(fwd, text="远程地址").grid(row=1, column=0, sticky="w", **pad)
        self._entry(fwd, self.var_remote_host, width=14).grid(row=1, column=1, sticky="w", **pad)
        ttk.Label(fwd, text="DSH 在服务器上监听的地址（通常 127.0.0.1）").grid(
            row=1, column=2, sticky="w", **pad)

        ttk.Label(fwd, text="远程端口").grid(row=2, column=0, sticky="w", **pad)
        self._entry(fwd, self.var_remote_port, width=8).grid(row=2, column=1, sticky="w", **pad)
        ttk.Label(fwd, text="DSH 端口（默认 3080）").grid(row=2, column=2, sticky="w", **pad)

        # 按钮
        btns = ttk.Frame(main)
        btns.pack(fill="x", pady=(0, 8))
        self.btn_start = ttk.Button(btns, text="一键启动隧道", command=self.start_tunnel)
        self.btn_start.pack(side="left", padx=(0, 6))
        self.btn_stop = ttk.Button(btns, text="停止隧道", command=self.stop_tunnel, state="disabled")
        self.btn_stop.pack(side="left", padx=(0, 6))
        self.btn_open = ttk.Button(btns, text="打开 DSH 界面", command=self.open_browser)
        self.btn_open.pack(side="left", padx=(0, 6))
        self.btn_test = ttk.Button(btns, text="测试连接", command=self.test_connection)
        self.btn_test.pack(side="left", padx=(0, 6))
        self.btn_save = ttk.Button(btns, text="保存配置", command=self.save_ui_config)
        self.btn_save.pack(side="right")

        # 状态栏
        status_frame = ttk.Frame(main)
        status_frame.pack(fill="x", pady=(0, 6))
        ttk.Label(status_frame, text="状态：").pack(side="left")
        self.status_label = ttk.Label(status_frame, textvariable=self.var_status, foreground="#888888")
        self.status_label.pack(side="left")

        # 日志
        log_frame = ttk.LabelFrame(main, text="日志", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log_text = ScrolledText(log_frame, height=10, state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)

    def _entry(self, parent, var, show=None, width=None):
        e = ttk.Entry(parent, textvariable=var, width=width or 36)
        if show:
            e.configure(show=show)
        return e

    # ---- 队列 -> 主线程更新 ----
    def _enqueue(self, kind, msg):
        self._q.put((kind, msg))

    def _poll_queue(self):
        try:
            while True:
                kind, msg = self._q.get_nowait()
                if kind == "log":
                    self._apply_log(msg)
                elif kind == "status":
                    self._apply_status(msg)
                elif kind == "error":
                    messagebox.showerror("提示", msg)
                elif kind == "info":
                    messagebox.showinfo("提示", msg)
                elif kind == "buttons":
                    self._sync_buttons()
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    def _on_log(self, msg):
        self._enqueue("log", msg)

    def _on_status(self, msg):
        self._enqueue("status", msg)

    def _apply_log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", "[%s] %s\n" % (ts, msg))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _apply_status(self, msg):
        self.var_status.set(msg)
        if msg == "未连接":
            color = "#888888"
        elif msg.startswith("已连接"):
            color = "#1a7f37"
        else:
            color = "#b35900"
        self.status_label.configure(foreground=color)

    # ---- 配置 ----
    def _load_to_ui(self):
        self._refresh_profile_list()
        self._load_profile(self.cfg["profiles"][self.active_profile])

    def _load_profile(self, p):
        self.var_host.set(p.get("host", ""))
        self.var_ssh_port.set(str(p.get("ssh_port", 22)))
        self.var_username.set(p.get("username", "root"))
        self.var_key_path.set(p.get("key_path", ""))
        self.var_passphrase.set(p.get("passphrase", ""))
        self.var_remember_pass.set(bool(p.get("remember_passphrase", False)))
        self.var_password.set(p.get("password", ""))
        self.var_local_port.set(str(p.get("local_port", 3080)))
        self.var_remote_host.set(p.get("remote_host", "127.0.0.1"))
        self.var_remote_port.set(str(p.get("remote_port", 3080)))

    def _refresh_profile_list(self):
        self.profile_combo.configure(values=list(self.cfg["profiles"].keys()))
        self.var_profile.set(self.active_profile)

    def _on_profile_selected(self, event=None):
        name = self.var_profile.get().strip()
        if not name or name not in self.cfg["profiles"]:
            return
        self.active_profile = name
        self.cfg["active_profile"] = name
        self._load_profile(self.cfg["profiles"][name])
        self._refresh_profile_list()
        self._on_log("已切换到配置预设：%s" % name)

    def add_profile(self):
        name = simpledialog.askstring("新建配置预设", "请输入配置名称：", parent=self.root)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        if name in self.cfg["profiles"]:
            messagebox.showwarning("提示", "配置名称“%s”已存在。" % name)
            return
        self.cfg["profiles"][name] = dict(DEFAULT_PROFILE)
        self.cfg["active_profile"] = name
        self.active_profile = name
        self._refresh_profile_list()
        self._load_profile(self.cfg["profiles"][name])
        save_config(self.cfg)
        self._on_log("已新建配置预设：%s" % name)

    def rename_profile(self):
        old = self.active_profile
        name = simpledialog.askstring("重命名配置预设", "新名称：", initialvalue=old, parent=self.root)
        if not name:
            return
        name = name.strip()
        if not name or name == old:
            return
        if name in self.cfg["profiles"]:
            messagebox.showwarning("提示", "配置名称“%s”已存在。" % name)
            return
        self.cfg["profiles"][name] = self.cfg["profiles"].pop(old)
        self.cfg["active_profile"] = name
        self.active_profile = name
        self._refresh_profile_list()
        save_config(self.cfg)
        self._on_log("配置预设已重命名：%s -> %s" % (old, name))

    def delete_profile(self):
        if len(self.cfg["profiles"]) <= 1:
            messagebox.showinfo("提示", "至少保留一个配置预设。")
            return
        name = self.active_profile
        if not messagebox.askyesno("删除配置预设", "确定删除配置预设“%s”？" % name, parent=self.root):
            return
        del self.cfg["profiles"][name]
        self.active_profile = next(iter(self.cfg["profiles"]))
        self.cfg["active_profile"] = self.active_profile
        self._refresh_profile_list()
        self._load_profile(self.cfg["profiles"][self.active_profile])
        save_config(self.cfg)
        self._on_log("已删除配置预设：%s" % name)

    def _collect_config(self):
        def parse_port(v, name):
            s = (v or "").strip()
            if not s.isdigit() or not (1 <= int(s) <= 65535):
                raise ValueError("%s 必须是 1-65535 之间的整数。" % name)
            return int(s)

        host = self.var_host.get().strip()
        if not host:
            raise ValueError("请填写服务器地址。")
        username = self.var_username.get().strip()
        if not username:
            raise ValueError("请填写用户名。")

        cfg = {
            "host": host,
            "ssh_port": parse_port(self.var_ssh_port.get(), "SSH 端口"),
            "username": username,
            "key_path": self.var_key_path.get().strip(),
            "password": self.var_password.get(),
            "passphrase": self.var_passphrase.get(),
            "remember_passphrase": self.var_remember_pass.get(),
            "local_host": "127.0.0.1",
            "local_port": parse_port(self.var_local_port.get(), "本地端口"),
            "remote_host": self.var_remote_host.get().strip() or "127.0.0.1",
            "remote_port": parse_port(self.var_remote_port.get(), "远程端口"),
        }
        return cfg

    def _save_cfg(self, cfg):
        stored = dict(cfg)
        # 私钥口令仅在勾选“记住口令”时保存；SSH 密码仅本次会话使用，不落盘
        if not stored.get("remember_passphrase"):
            stored["passphrase"] = ""
        stored["password"] = ""
        self.cfg["profiles"][self.active_profile] = stored
        save_config(self.cfg)

    def save_ui_config(self):
        try:
            cfg = self._collect_config()
        except Exception as e:
            messagebox.showerror("无法保存", str(e))
            return
        self._save_cfg(cfg)
        self._on_log("已保存配置预设：%s" % self.active_profile)

    # ---- 选择 / 保存私钥 ----
    def choose_key(self):
        path = filedialog.askopenfilename(
            title="选择 SSH 私钥文件",
            filetypes=[("SSH 私钥 / 所有文件", "*.*"),
                       ("PEM 私钥", "*.pem"), ("KEY 文件", "*.key")],
        )
        if not path:
            return
        os.makedirs(KEYS_DIR, exist_ok=True)
        base = os.path.basename(path)
        dest = os.path.join(KEYS_DIR, base)
        if os.path.exists(dest) and not files_equal(path, dest):
            stem, ext = os.path.splitext(base)
            i = 1
            while os.path.exists(os.path.join(KEYS_DIR, "%s_%d%s" % (stem, i, ext))):
                i += 1
            dest = os.path.join(KEYS_DIR, "%s_%d%s" % (stem, i, ext))
        shutil.copyfile(path, dest)
        rel = os.path.relpath(dest, APP_DIR)
        self.var_key_path.set(rel)
        self._on_log("私钥已保存到：%s" % rel)
        self.save_ui_config()

    # ---- 按钮逻辑 ----
    def _sync_buttons(self):
        running = bool(self.tunnel and self.tunnel.running)
        busy = running or self._connecting
        self.btn_start.configure(state="disabled" if busy else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.btn_test.configure(state="disabled" if busy else "normal")

    def start_tunnel(self):
        if paramiko is None:
            messagebox.showerror("缺少依赖", "未安装 paramiko。\n请运行：pip install paramiko")
            return
        if self.tunnel and self.tunnel.running:
            messagebox.showinfo("提示", "隧道已经在运行中。")
            return
        try:
            cfg = self._collect_config()
        except Exception as e:
            messagebox.showerror("配置错误", str(e))
            return
        self._save_cfg(cfg)

        self._connecting = True
        self._sync_buttons()
        self._on_status("正在连接...")
        self._on_log("正在建立 SSH 连接...")

        self.tunnel = SSHTunnel(cfg, on_status=self._on_status, on_log=self._on_log)

        def worker():
            try:
                self.tunnel.start()
                self._on_log("隧道运行中，点击“打开 DSH 界面”即可访问。")
            except Exception as e:
                self.tunnel.stop()
                self._on_status("未连接")
                self._on_log("启动失败：%s" % e)
                self._enqueue("error", "启动失败：\n%s" % e)
            finally:
                self._connecting = False
                self._enqueue("buttons", None)

        threading.Thread(target=worker, daemon=True).start()

    def stop_tunnel(self):
        if self.tunnel:
            self.tunnel.stop()
        self._sync_buttons()

    def test_connection(self):
        if paramiko is None:
            messagebox.showerror("缺少依赖", "未安装 paramiko。\n请运行：pip install paramiko")
            return
        if self.tunnel and self.tunnel.running:
            messagebox.showinfo("提示", "隧道正在运行，连接正常。")
            return
        try:
            cfg = self._collect_config()
        except Exception as e:
            messagebox.showerror("配置错误", str(e))
            return
        self._save_cfg(cfg)

        self._connecting = True
        self._sync_buttons()
        self._on_status("正在测试连接...")
        self._on_log("正在测试 SSH 连接...")

        def worker():
            t = SSHTunnel(cfg)
            try:
                t.connect()
                t.disconnect()
                self._on_status("未连接")
                self._on_log("连接测试成功：%s@%s:%s 可达。"
                             % (cfg["username"], cfg["host"], cfg["ssh_port"]))
                self._enqueue("info", "SSH 连接测试成功！")
            except Exception as e:
                self._on_status("未连接")
                self._on_log("连接测试失败：%s" % e)
                self._enqueue("error", "SSH 连接测试失败：\n%s" % e)
            finally:
                self._connecting = False
                self._enqueue("buttons", None)

        threading.Thread(target=worker, daemon=True).start()

    def open_browser(self):
        port = self.var_local_port.get().strip() or "3080"
        url = "http://127.0.0.1:%s" % port
        webbrowser.open(url)
        self._on_log("已打开浏览器：%s" % url)

    def on_close(self):
        try:
            if self.tunnel and self.tunnel.running:
                self.tunnel.stop()
        finally:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
