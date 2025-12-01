# -*- coding: utf-8 -*-
import serial
import socket
import time
import threading
import functools
import operator
import tkinter as tk
from tkinter import ttk, messagebox
from serial.tools import list_ports
import struct
import subprocess
import sys

# === [자동 업데이트용 표준 라이브러리] ===
import os, json, hashlib, shutil, tempfile, subprocess as sp
import urllib.request

# ---------------------------
# 앱 버전 / 깃허브 설정
# ---------------------------
__VERSION__ = "3.0.0"                 # 현재 앱 버전
GITHUB_OWNER = "sms7703"              # 깃허브 아이디
GITHUB_REPO  = "POINT-ANEMO"          # 리포 이름
ASSET_NAME_PREFIX = "풍향풍속계 통합테스터 MS ver"  # 릴리스 자산 파일 접두사(한글 OK)

GITHUB_LATEST_API = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
USER_AGENT = "AnemoTester-Updater"

def _parse_version(v: str):
    v = v.strip().lstrip('vV')
    parts = v.split('.')
    return tuple(int(p) for p in parts if p.isdigit())

def _is_newer(remote: str, local: str) -> bool:
    try:
        return _parse_version(remote) > _parse_version(local)
    except:
        return False

def _gh_get_latest_release():
    req = urllib.request.Request(GITHUB_LATEST_API, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))
    tag = data.get("tag_name") or ""
    assets = data.get("assets", [])
    exe_asset = None
    sha_asset = None
    for a in assets:
        name = a.get("name","")
        # 접두사 + .exe 자산 찾기(한글/공백 지원)
        if name.lower().endswith(".exe") and name.startswith(ASSET_NAME_PREFIX):
            exe_asset = a
        elif name.lower().endswith(".sha256"):
            sha_asset = a
    return tag, exe_asset, sha_asset

def _download(url: str, outpath: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r, open(outpath, "wb") as f:
        shutil.copyfileobj(r, f)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _read_sha256_from_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            first = f.read().strip().split()
            if first:
                return first[0]
    except:
        pass
    return ""

# --- PowerShell 기반 교체 스크립트(유니코드/공백 경로 안전) ---
def _write_replace_and_restart_ps1(current_exe: str, new_exe: str):
    ps = f"""
$ErrorActionPreference = "Stop"
Start-Sleep -Milliseconds 800

# 현재 실행 파일이 잠금 해제될 때까지 삭제 재시도
$tries = 0
while (Test-Path "{current_exe}") {{
    try {{
        Remove-Item -LiteralPath "{current_exe}" -Force
        break
    }} catch {{
        $tries += 1
        if ($tries -gt 50) {{ break }}
        Start-Sleep -Milliseconds 200
    }}
}}

if (Test-Path "{current_exe}") {{
    try {{ Remove-Item -LiteralPath "{current_exe}" -Force }} catch {{}}
}}

Move-Item -LiteralPath "{new_exe}" -Destination "{current_exe}" -Force
Start-Process -FilePath "{current_exe}"

$me = $MyInvocation.MyCommand.Path
Start-Sleep -Milliseconds 500
Remove-Item -LiteralPath $me -Force
"""
    fd, ps1_path = tempfile.mkstemp(prefix="anemo_update_", suffix=".ps1")
    os.close(fd)
    with open(ps1_path, "w", encoding="utf-8") as f:
        f.write(ps)
    return ps1_path

def _run_replacer_and_exit(current_exe: str, new_exe: str, parent_window=None):
    ps1 = _write_replace_and_restart_ps1(current_exe, new_exe)
    sp.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1],
        creationflags=0x00000008,  # DETACHED_PROCESS
        close_fds=True
    )
    if parent_window is not None:
        try:
            parent_window.after(100, parent_window.destroy)
        except:
            os._exit(0)
    else:
        os._exit(0)

def check_and_maybe_update(parent_window=None):
    if getattr(sys, 'frozen', False):
        current_exe = sys.executable
    else:
        current_exe = os.path.abspath(sys.argv[0])

    try:
        tag, exe_asset, sha_asset = _gh_get_latest_release()
    except Exception:
        return

    if not tag or not exe_asset:
        return

    remote_ver = tag
    if not _is_newer(remote_ver, __VERSION__):
        return

    if not messagebox.askyesno("업데이트 확인", f"새 버전 {remote_ver}이(가) 있습니다.\n지금 업데이트할까요?"):
        return

    tmp_dir = tempfile.mkdtemp(prefix="anemo_dl_")
    new_exe_path = os.path.join(tmp_dir, exe_asset["name"])
    try:
        _download(exe_asset["browser_download_url"], new_exe_path)

        if sha_asset:
            sha_path = os.path.join(tmp_dir, sha_asset["name"])
            _download(sha_asset["browser_download_url"], sha_path)
            want = _read_sha256_from_text(sha_path).lower()
            got  = _sha256_file(new_exe_path).lower()
            if want and want != got:
                messagebox.showerror("업데이트 실패", "무결성 검증 실패(sha256 불일치)")
                return

        _run_replacer_and_exit(current_exe, new_exe_path, parent_window)

    except Exception as e:
        messagebox.showerror("업데이트 실패", f"{e}")
        return

# ---------------------------
# 전역 상태 변수
# ---------------------------
current_speed = 0.0
current_direction = 0
is_paused = False

stop_event = threading.Event()
gui_lock = threading.Lock()

# --- 설정 ---
DEFAULT_INTERVAL = 1.0
BAUDRATES = [2400, 4800, 9600, 19200, 38400]

COMM_FORMATS = ["WMT52 (NMEA)", "703 (Binary)", "Blue Sonic"]
MODES = ["시리얼 통신", "랜 통신"]

OP_MODE_WRITE = "쓰기 모드 (Simulator)"
OP_MODE_READ = "읽기 모드 (Monitor/Poller)"
OP_MODES_ALL = [OP_MODE_WRITE, OP_MODE_READ]
OP_MODES_READ_ONLY = [OP_MODE_READ]

# 703 포맷 상수
HEADER_703 = 0x01
LENGTH_703 = 0x06

# 703 방향 스케일 (0~359도를 0~32767 정수로 매핑)
SCALE_703_DIR = 32767 / 360.0

# ================================
# 데이터 생성 로직
# ================================
def calculate_checksum_nmea(sentence_body):
    checksum = functools.reduce(operator.xor, (ord(c) for c in sentence_body))
    return f"*{checksum:02X}"

def create_nmea_sentence(direction, speed, format_type="WMT52"):
    dir_str = f"{int(direction):03d}"
    speed_str = f"{float(speed):.1f}"
    if "Blue Sonic" in format_type:
        body = f"WIMWV,{speed_str},R,{dir_str},M,A"
    else:
        body = f"WIMWV,{dir_str},R,{speed_str},M,A"
    return f"${body}{calculate_checksum_nmea(body)}\r\n"

def create_703_sentence(direction, speed):
    try:
        dir_val = float(direction)
        spd_val = float(speed)
    except:
        dir_val = 0.0
        spd_val = 0.0

    if dir_val < 0.0: dir_val = 0.0
    if dir_val > 359.0: dir_val = 359.0

    direction_scaled = int(round(dir_val * SCALE_703_DIR))
    speed_scaled = int(spd_val * 40)

    data_payload = struct.pack('<BB', HEADER_703, LENGTH_703)
    data_payload += struct.pack('>H', direction_scaled)
    data_payload += struct.pack('>H', speed_scaled)

    xor_sum = 0
    for byte in data_payload:
        xor_sum ^= byte
    checksum = xor_sum ^ 0x33

    final_bytes = data_payload + struct.pack('B', checksum)
    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes

# ================================
# 송신 스레드
# ================================
def sender_thread(comm, app_instance):
    global current_speed, current_direction, is_paused

    last_log_time = 0
    next_tick = time.monotonic()

    while not stop_event.is_set():
        if is_paused:
            stop_event.wait(0.05)
            continue

        try:
            interval = float(app_instance.interval_var.get())
        except:
            interval = DEFAULT_INTERVAL
        if interval < 0.001:
            interval = 0.001

        baud_rate = app_instance.baud_var.get()
        if baud_rate == 2400:
            real_interval = max(interval, 0.04)
        else:
            real_interval = interval

        op_mode = app_instance.op_mode_var.get()
        comm_fmt = app_instance.format_var.get()

        data_to_send = None
        msg_display = ""
        tx_status_text = ""

        cur_spd = current_speed
        cur_dir = current_direction

        if op_mode == OP_MODE_WRITE:
            if comm['mode'] == "랜 통신":
                tx_status_text = "오류: LAN은 쓰기 모드를 지원하지 않습니다."
                data_to_send = None
            else:
                if "703" in comm_fmt:
                    if baud_rate != 2400:
                        tx_status_text = "전송 불가: 703 모드는 2400bps 전용입니다."
                        data_to_send = None
                    else:
                        hex_str, binary_data = create_703_sentence(cur_dir, cur_spd)
                        tx_status_text = f"송신(703): 풍속:{cur_spd:.1f} 풍향:{cur_dir}°"
                        msg_display = f"HEX: {hex_str}"
                        data_to_send = binary_data
                else:
                    tx_status_text = f"송신(NMEA): 풍속:{cur_spd:.1f} 풍향:{cur_dir}°"
                    msg_display = create_nmea_sentence(cur_dir, cur_spd, comm_fmt)
                    data_to_send = msg_display.encode('ascii')

        elif op_mode == OP_MODE_READ:
            polling_cmd = app_instance.poll_cmd_var.get().strip()
            if "703" in comm_fmt:
                tx_status_text = "송신 데이터: (대기 중 - 수신 모드)"
                data_to_send = None
            elif polling_cmd:
                tx_status_text = f"송신 데이터: {polling_cmd} (Polling...)"
                full_cmd = polling_cmd
                if not full_cmd.endswith('\r') and not full_cmd.endswith('\n'):
                    full_cmd += "\r\n"
                data_to_send = full_cmd.encode('ascii')
                msg_display = full_cmd.strip()
            else:
                data_to_send = None
                tx_status_text = "송신 데이터: (대기 중 - 수신 모드)"

        if data_to_send:
            try:
                if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                    ser = comm['ser']
                    ser.write(data_to_send)
                    if ser.out_waiting and ser.out_waiting > 256:
                        ser.flush()
                    current_time = time.time()
                    if current_time - last_log_time > 0.3:
                        if op_mode == OP_MODE_WRITE:
                            app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                        last_log_time = current_time
                    app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

                elif comm['mode'] == "랜 통신" and comm.get('sock'):
                    comm['sock'].sendall(data_to_send)
                    current_time = time.time()
                    if current_time - last_log_time > 0.3:
                        app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                        last_log_time = current_time
                    app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

            except Exception as e:
                app_instance.master.after(0, app_instance.update_gui_log, f"[TX ERR] {e}")
                if "LAN" in comm['mode']:
                    stop_event.set()
                    break
        else:
            app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

        next_tick += real_interval
        now = time.monotonic()
        sleep_for = next_tick - now
        if sleep_for > 0:
            stop_event.wait(sleep_for)
        else:
            next_tick = now

# ================================
# 수신 스레드
# ================================
def receiver_thread(comm, app_instance):
    while not stop_event.is_set():
        if is_paused:
            stop_event.wait(0.05)
            continue

        if app_instance.op_mode_var.get() == OP_MODE_WRITE:
            try:
                if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                    ser = comm['ser']
                    if ser.in_waiting:
                        _ = ser.read(ser.in_waiting)
                elif comm['mode'] == "랜 통신" and comm.get('sock'):
                    comm['sock'].settimeout(0.0)
                    try:
                        while True:
                            chunk = comm['sock'].recv(4096)
                            if not chunk:
                                break
                    except:
                        pass
            except:
                pass
            stop_event.wait(0.05)
            continue

        try:
            data = b''
            source = ""
            current_fmt = app_instance.format_var.get()

            if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                ser = comm['ser']
                try:
                    if ser.in_waiting:
                        stop_event.wait(0.02)
                        data = ser.read(ser.in_waiting)
                        source = "SER"
                    else:
                        stop_event.wait(0.01)
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[SER ERR] {e}")
                    stop_event.wait(0.5)

            elif comm['mode'] == "랜 통신" and comm.get('sock'):
                sock = comm['sock']
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ConnectionResetError("Remote closed")
                    data = chunk
                    source = "LAN"
                except socket.timeout:
                    pass
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[LAN ERR] {e}")
                    stop_event.set()
                    break

            if data:
                hex_str = ' '.join(f'{b:02X}' for b in data)
                try:
                    text_str = data.decode('ascii', errors='ignore').strip()
                except:
                    text_str = "..."

                is_noise = False
                if "703" not in current_fmt:
                    if not text_str.startswith('$') and "R000" not in text_str:
                        is_noise = True

                if not is_noise:
                    if "703" in current_fmt:
                        log_msg = f"RX({source}): [HEX: {hex_str}]"
                    elif b'R000:' in data:
                        log_msg = f"RX({source}): {text_str}  [HEX: {hex_str}]"
                    else:
                        log_msg = f"RX({source}): {text_str}"
                    app_instance.master.after(0, app_instance.update_gui_log, log_msg)

                parse_result = "해석 불가"

                if "703" in current_fmt:
                    found_703 = False
                    data_len = len(data)
                    for i in range(data_len - 6):
                        if data[i] == HEADER_703 and data[i + 1] == LENGTH_703:
                            packet = data[i:i + 7]
                            received_cs = packet[6]
                            xor_sum = 0
                            for b in packet[:6]:
                                xor_sum ^= b
                            calc_cs = xor_sum ^ 0x33
                            if received_cs == calc_cs:
                                try:
                                    dir_raw = struct.unpack('>H', packet[2:4])[0]
                                    spd_raw = struct.unpack('>H', packet[4:6])[0]

                                    spd = spd_raw / 40.0
                                    ang = dir_raw / SCALE_703_DIR

                                    if ang < 0.0: ang = 0.0
                                    elif ang > 359.0: ang = 359.0

                                    parse_result = f"수신(703): 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}°"
                                    found_703 = True
                                    break
                                except:
                                    pass
                    if not found_703 and len(data) >= 2 and data[0] == HEADER_703 and data[1] == LENGTH_703:
                        parse_result = "703 헤더 감지됨 (체크섬/길이 부족)"

                else:
                    if b"$WIMWV" in data:
                        try:
                            lines = text_str.splitlines()
                            for line in lines:
                                if "WIMWV" in line:
                                    parts = line.split(',')
                                    if len(parts) >= 5:
                                        val1 = float(parts[1]) if parts[1] else 0.0
                                        val3 = float(parts[3]) if parts[3] else 0.0
                                        if "Blue Sonic" in current_fmt:
                                            spd, ang = val1, val3
                                        else:
                                            ang, spd = val1, val3
                                        parse_result = f"수신(NMEA): 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}°"
                                        break
                        except:
                            parse_result = "NMEA 파싱 오류"
                    elif b'R000:' in data:
                        try:
                            start_idx = data.find(b'R000:')
                            if start_idx != -1 and len(data) >= start_idx + 13:
                                payload = data[start_idx + 5: start_idx + 13]
                                val1, val2 = struct.unpack('<ff', payload)
                                parse_result = f"수신(R000): 풍속: {val2:.1f} m/s, 풍향: {val1:.1f}°"
                            else:
                                parse_result = "R000 데이터 길이 부족"
                        except Exception as e:
                            parse_result = f"R000 파싱 오류: {e}"

                if parse_result != "해석 불가":
                    if app_instance.op_mode_var.get() == OP_MODE_READ:
                        app_instance.master.after(0, app_instance.update_parsed_data, parse_result)

        except Exception as e:
            if not stop_event.is_set():
                print(f"Recv Error: {e}")
            time.sleep(1)

# ================================
# GUI Application
# ================================
class AnemometerTesterApp:
    def __init__(self, master):
        self.master = master
        self.master.title(f"풍향풍속계 통합테스터 MS ver {__VERSION__}")

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.geometry("800x750")
        self.master.resizable(True, True)

        self.comm = {'mode': MODES[0], 'ser': None, 'sock': None}
        self.sender_thread = None
        self.receiver_thread = None

        self.op_mode_var = tk.StringVar(value=OP_MODE_WRITE)
        self.mode_var = tk.StringVar(value=MODES[0])
        self.format_var = tk.StringVar(value=COMM_FORMATS[0])
        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=4800)
        self.ip_var = tk.StringVar(value="192.168.0.2")
        self.lan_port_var = tk.IntVar(value=4000)
        self.interval_var = tk.StringVar(value="1.0")
        self.poll_cmd_var = tk.StringVar(value="R000?")
        self.speed_var = tk.StringVar(value="0.0")
        self.direction_var = tk.StringVar(value="0")
        self.my_local_ip_var = tk.StringVar(value="확인 중...")
        self.sim_status_var = tk.StringVar(value="현재 송신 설정값: 설정 필요")
        self.status_var = tk.StringVar(value="대기 중")
        self.rx_display_var = tk.StringVar(value="수신 데이터: 대기 중...")
        self.tx_display_var = tk.StringVar(value="송신 데이터: 대기 중...")

        # 패치노트
        self.patch_win = None
        self.patch_note_text = (
            "=== 패치노트 ===\n"
            f"최종버전:{__VERSION__}\n\n"
            "1) GitHub 릴리스 기반 자동 업데이트(PowerShell 교체) 내장\n"
            "2) 사용법(F1) 간단 정리, 버튼 상단 배치\n"
            "3) 703 스케일 32767/360 유지, 파서 안정화\n"
        )

        # 사용법(간단 버전)
        self.help_win = None
        self.usage_text = (
            "=== 사용법 ===\n"
            "1) 통신 선택\n"
            "   - 시리얼 통신: PC ↔ 390\n"
            "     · 703(Binary): Baud 2400 필수\n"
            "     · WMT52(NMEA): Baud 4800 필수\n"
            "   - 랜 통신: PWM-2000(WMT52) 수신 전용 (쓰기 불가)\n"
            "\n"
            "2) 동작 모드\n"
            "   - 쓰기: 시뮬레이션 데이터 송신\n"
            "   - 읽기: 센서 수신 / 필요 시 폴링 명령 사용\n"
        )

        self.create_ui()
        self.update_port_list()
        self.check_my_ip()
        self.master.after(10, self.on_mode_change)

        # F1 사용법
        self.master.bind("<F1>", lambda e: self.open_usage_help())

        # 실행 후 자동 업데이트 확인
        self.master.after(1500, lambda: check_and_maybe_update(self.master))

    def check_my_ip(self):
        try:
            hostname = socket.gethostname()
            all_ips = socket.gethostbyname_ex(hostname)[2]
            valid_ips = [ip for ip in all_ips if not ip.startswith("127.")]
            if valid_ips:
                self.my_local_ip_var.set(" / ".join(valid_ips))
            else:
                self.my_local_ip_var.set("IP 찾기 실패 (네트워크 확인)")
        except Exception:
            self.my_local_ip_var.set("확인 불가")

    def open_system_settings(self):
        mode = self.mode_var.get()
        try:
            if 'win' in sys.platform:
                if "랜 통신" in mode:
                    subprocess.Popen('ncpa.cpl', shell=True)
                else:
                    subprocess.Popen('devmgmt.msc', shell=True)
            else:
                messagebox.showinfo("정보", "이 기능은 Windows 환경에서만 작동합니다.")
        except Exception as e:
            messagebox.showerror("오류", f"설정 창을 열 수 없습니다: {e}")

    def open_patch_note(self):
        if self.patch_win is not None and self.patch_win.winfo_exists():
            self.patch_win.lift()
            return
        self.patch_win = tk.Toplevel(self.master)
        self.patch_win.title("Patch Note")
        self.patch_win.geometry("320x240")
        self.patch_win.resizable(False, False)
        ttk.Label(self.patch_win, text="Patch Note", font=("Malgun Gothic", 11, "bold")).pack(anchor="center", pady=(10, 5))
        text_widget = tk.Text(self.patch_win, height=12, width=40, wrap="word")
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        text_widget.insert("1.0", self.patch_note_text)
        text_widget.config(state="disabled")

    def open_usage_help(self):
        if self.help_win is not None and self.help_win.winfo_exists():
            self.help_win.lift()
            return
        self.help_win = tk.Toplevel(self.master)
        self.help_win.title("사용법")
        self.help_win.geometry("360x320")
        self.help_win.resizable(False, False)
        ttk.Label(self.help_win, text="사용법 (F1)", font=("Malgun Gothic", 11, "bold")).pack(anchor="center", pady=(10, 5))
        text_widget = tk.Text(self.help_win, height=16, width=46, wrap="word")
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        text_widget.insert("1.0", self.usage_text)
        text_widget.config(state="disabled")

    def create_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # 상단 버튼: 사용법(F1), 패치노트
        self.btn_help = ttk.Button(self.master, text="사용법(F1)", width=10, command=self.open_usage_help)
        self.btn_help.place(relx=1.0, x=-100, y=10, anchor="ne")
        self.btn_patch = ttk.Button(self.master, text="패치노트", width=8, command=self.open_patch_note)
        self.btn_patch.place(relx=1.0, x=-10, y=10, anchor="ne")

        info_frame = ttk.LabelFrame(main_frame, text="실시간 데이터 상태", padding=10)
        info_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        self.lbl_rx = ttk.Label(info_frame, textvariable=self.rx_display_var, font=("Malgun Gothic", 16, "bold"), foreground="blue")
        self.lbl_rx.pack(anchor="center", pady=2)
        self.lbl_tx = ttk.Label(info_frame, textvariable=self.tx_display_var, font=("Malgun Gothic", 16, "bold"), foreground="red")
        self.lbl_tx.pack(anchor="center", pady=2)

        conn_frame = ttk.LabelFrame(main_frame, text="1. 통신 연결 설정", padding=10)
        conn_frame.grid(row=1, column=0, padx=5, sticky="nsew")
        conn_frame.columnconfigure(0, weight=1)

        mode_select_frame = ttk.Frame(conn_frame)
        mode_select_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        mode_select_frame.columnconfigure(1, weight=1)
        ttk.Label(mode_select_frame, text="통신 방식:").grid(row=0, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(mode_select_frame, textvariable=self.mode_var, values=MODES, state="readonly")
        self.mode_combo.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_mode_change())

        self.settings_container = ttk.Frame(conn_frame)
        self.settings_container.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.settings_container.columnconfigure(0, weight=1)

        self.serial_frame = ttk.Frame(self.settings_container)
        self.serial_frame.grid(row=0, column=0, sticky="nsew")
        self.serial_frame.columnconfigure(1, weight=1)
        ttk.Label(self.serial_frame, text="Port:").grid(row=0, column=0, sticky="w")
        self.port_combo = ttk.Combobox(self.serial_frame, textvariable=self.port_var, width=8)
        self.port_combo.grid(row=0, column=1, sticky="ew", padx=(5, 5))
        self.btn_refresh = ttk.Button(self.serial_frame, text="새로고침", command=self.update_port_list, width=10)
        self.btn_refresh.grid(row=0, column=2, sticky="w", padx=(0, 10))
        ttk.Label(self.serial_frame, text="Baud:").grid(row=0, column=3, sticky="w")
        self.baud_combo = ttk.Combobox(self.serial_frame, textvariable=self.baud_var, values=BAUDRATES, width=7, state="readonly")
        self.baud_combo.grid(row=0, column=4, sticky="w")

        self.lan_frame = ttk.Frame(self.settings_container)
        self.lan_frame.grid(row=0, column=0, sticky="nsew")
        self.lan_frame.columnconfigure(1, weight=1)
        ttk.Label(self.lan_frame, text="타겟 IP:").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.lan_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="ew", padx=(5, 10))
        ttk.Label(self.lan_frame, text="Port:").grid(row=0, column=2, sticky="w")
        ttk.Entry(self.lan_frame, textvariable=self.lan_port_var, width=5).grid(row=0, column=3, sticky="w")
        ttk.Label(self.lan_frame, text="내 PC IP:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(self.lan_frame, textvariable=self.my_local_ip_var, foreground="blue").grid(row=1, column=1, columnspan=3, sticky="w", pady=(5, 0), padx=5)

        self.btn_system_settings = ttk.Button(conn_frame, text="장치 관리자", command=self.open_system_settings)
        self.btn_system_settings.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))

        self.btn_connect = ttk.Button(conn_frame, text="연결 하기", command=self.connect)
        self.btn_connect.grid(row=3, column=0, columnspan=2, pady=(10, 5), sticky="ew")

        self.btn_disconnect = ttk.Button(conn_frame, text="연결 종료", command=self.disconnect, state=tk.DISABLED)
        self.btn_disconnect.grid(row=4, column=0, columnspan=2, sticky="ew")

        op_frame = ttk.LabelFrame(main_frame, text="2. 동작 모드 설정", padding=10)
        op_frame.grid(row=1, column=1, padx=5, sticky="nsew")
        op_frame.columnconfigure(1, weight=1)

        ttk.Label(op_frame, text="동작 모드:").grid(row=0, column=0, sticky="w", pady=5)
        self.op_mode_combo = ttk.Combobox(op_frame, textvariable=self.op_mode_var, values=OP_MODES_ALL, state="readonly")
        self.op_mode_combo.grid(row=0, column=1, sticky="ew", pady=5, padx=5)
        self.op_mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_op_mode_change())

        ttk.Label(op_frame, text="데이터 포맷:").grid(row=1, column=0, sticky="w", pady=5)
        self.format_combo = ttk.Combobox(op_frame, textvariable=self.format_var, values=COMM_FORMATS, state="readonly")
        self.format_combo.grid(row=1, column=1, sticky="ew", pady=5, padx=5)

        ttk.Label(op_frame, text="전송 주기(초):").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(op_frame, textvariable=self.interval_var, width=10).grid(row=2, column=1, sticky="w", pady=5, padx=5)

        self.detail_frame = ttk.Frame(op_frame, height=100)
        self.detail_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        self.detail_frame.grid_propagate(False)
        self.detail_frame.columnconfigure(0, weight=1)

        self.write_widgets_frame = ttk.Frame(self.detail_frame)
        self.write_widgets_frame.grid(row=0, column=0, sticky="nsew")
        self.write_widgets_frame.columnconfigure(0, weight=1)
        ttk.Label(self.write_widgets_frame, text="[시뮬레이션 값 설정]", foreground="brown").pack(anchor="w", fill=tk.X)
        w_sub = ttk.Frame(self.write_widgets_frame)
        w_sub.pack(fill=tk.X, pady=5)
        w_sub.columnconfigure(1, weight=1)
        w_sub.columnconfigure(3, weight=1)
        ttk.Label(w_sub, text="풍속:").grid(row=0, column=0, sticky="w")
        ttk.Entry(w_sub, textvariable=self.speed_var).grid(row=0, column=1, sticky="ew", padx=(5, 10))
        ttk.Label(w_sub, text="풍향:").grid(row=0, column=2, sticky="w")
        ttk.Entry(w_sub, textvariable=self.direction_var).grid(row=0, column=3, sticky="ew", padx=(5, 10))
        ttk.Button(w_sub, text="적용", width=5, command=self.apply_values).grid(row=0, column=4, sticky="e")
        ttk.Label(self.write_widgets_frame, textvariable=self.sim_status_var, foreground="gray", font=("Malgun Gothic", 9)).pack(anchor="c", pady=(5, 0))

        self.read_widgets_frame = ttk.Frame(self.detail_frame)
        self.read_widgets_frame.grid(row=0, column=0, sticky="nsew")
        self.read_widgets_frame.columnconfigure(0, weight=1)
        ttk.Label(self.read_widgets_frame, text="[폴링 명령어 (비워두면 수신 전용)]", foreground="green").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.read_widgets_frame, textvariable=self.poll_cmd_var).grid(row=1, column=0, sticky="ew", pady=(0, 5))
        ttk.Label(self.read_widgets_frame, text="* 자동 전송 센서는 위 칸을 비우세요.", foreground="gray", font=("Malgun Gothic", 8)).grid(row=2, column=0, sticky="w")
        ttk.Label(self.read_widgets_frame, text="* 703읽기모드는 WMT32포맷 4800속도 해야함", foreground="red", font=("Malgun Gothic", 8)).grid(row=3, column=0, sticky="w")

        self.btn_pause = ttk.Button(op_frame, text="일시 정지", command=self.toggle_pause, state=tk.DISABLED)
        self.btn_pause.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)

        log_frame = ttk.LabelFrame(main_frame, text="3. RAW 로그", padding=5)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, height=8, font=("Consolas", 9))
        scr = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scr.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scr.grid(row=0, column=1, sticky="ns")
        ttk.Button(log_frame, text="로그 지우기", command=lambda: self.log_text.delete(1.0, tk.END)).grid(row=1, column=0, sticky="e")

        self.lbl_status = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.lbl_status.pack(side=tk.BOTTOM, fill=tk.X)

    def update_port_list(self):
        ports = list_ports.comports()
        self.port_combo['values'] = [p.device for p in ports]
        if ports:
            self.port_var.set(ports[0].device)

    def on_mode_change(self):
        mode = self.mode_var.get()
        if "랜 통신" in mode:
            self.lan_frame.tkraise()
            self.btn_system_settings.config(state=tk.NORMAL, text="네트워크 설정")
            self.check_my_ip()
            self.op_mode_var.set(OP_MODE_READ)
            self.op_mode_combo.config(values=OP_MODES_READ_ONLY)
            self.op_mode_combo.config(state="disabled")
        else:
            self.serial_frame.tkraise()
            self.btn_system_settings.config(state=tk.NORMAL, text="장치 관리자")
            self.op_mode_combo.config(state="readonly")
            self.op_mode_combo.config(values=OP_MODES_ALL)
        self.on_op_mode_change()

    def on_op_mode_change(self):
        mode = self.op_mode_var.get()
        if mode == OP_MODE_WRITE:
            self.read_widgets_frame.grid_remove()
            self.write_widgets_frame.grid()
            self.format_combo.config(state="readonly")
            self.rx_display_var.set("수신 데이터: 대기 중... (송신 전용)")
        else:
            self.write_widgets_frame.grid_remove()
            self.read_widgets_frame.grid()
            self.format_combo.config(state="readonly")
            self.tx_display_var.set("송신 데이터: 대기 중... (수신 전용)")

    def apply_values(self):
        global current_speed, current_direction
        try:
            s_val = float(self.speed_var.get())
            d_val = float(self.direction_var.get())
            d_int = int(d_val)

            if not (0 <= s_val <= 99):
                messagebox.showwarning("범위 초과", "풍속(0 ~ 99)")
                return
            if not (0 <= d_int <= 359):
                messagebox.showwarning("범위 초과", "풍향(0 ~ 359)")
                return

            current_speed = s_val
            current_direction = d_int

            self.sim_status_var.set(f"설정값: 풍속 {s_val} m/s, 풍향 {d_int}°")
            self.update_gui_log(f">>> 값 변경: 풍속:{s_val}, 풍향:{d_int}")

        except ValueError:
            messagebox.showerror("입력 오류", "유효한 숫자를 입력하세요.")

    def toggle_pause(self):
        global is_paused
        is_paused = not is_paused
        paused_now = is_paused
        self.btn_pause.config(text="전송 재개" if is_paused else "일시 정지")
        msg_time = time.strftime('%H:%M:%S')
        if paused_now:
            self.update_gui_log(f"!!! 사용자 일시 정지 ({msg_time}) !!!")
        else:
            self.update_gui_log(f"!!! 동작 재개 ({msg_time}) !!!")

    def update_gui_log(self, msg):
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)

    def update_parsed_data(self, msg):
        self.rx_display_var.set(msg)

    def update_tx_data_ui(self, msg):
        self.tx_display_var.set(msg)

    def connect(self):
        global stop_event, is_paused
        stop_event.clear()
        is_paused = False
        self.btn_pause.config(text="일시 정지")

        mode = self.mode_var.get()
        self.comm['mode'] = mode

        try:
            if "시리얼 통신" in mode:
                port = self.port_var.get()
                baud = self.baud_var.get()

                self.comm['ser'] = serial.Serial(
                    port=port,
                    baudrate=baud,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=0.0,
                    write_timeout=0.05,
                    rtscts=False,
                    dsrdtr=False,
                    xonxoff=False,
                )
                try:
                    self.comm['ser'].reset_input_buffer()
                    self.comm['ser'].reset_output_buffer()
                except:
                    pass
                self.status_var.set(f"연결됨: {port} ({baud}bps)")
            else:
                ip = self.ip_var.get()
                port = int(self.lan_port_var.get())
                self.update_gui_log(f"LAN 연결 중... {ip}:{port}")
                sock = socket.create_connection((ip, port), timeout=3.0)
                sock.settimeout(0.1)
                self.comm['sock'] = sock
                self.status_var.set(f"연결됨: {ip}:{port}")

            self.sender_thread = threading.Thread(target=sender_thread, args=(self.comm, self), daemon=True)
            self.receiver_thread = threading.Thread(target=receiver_thread, args=(self.comm, self), daemon=True)
            self.sender_thread.start()
            self.receiver_thread.start()

            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
            self.btn_pause.config(state=tk.NORMAL)

            if "시리얼" in mode:
                self.btn_refresh.config(state=tk.DISABLED)
                self.port_combo.config(state="disabled")
                self.baud_combo.config(state="disabled")

            self.mode_combo.config(state="disabled")
            if "랜 통신" in mode:
                self.op_mode_combo.config(state="disabled")
            else:
                self.op_mode_combo.config(state="disabled")

        except Exception as e:
            messagebox.showerror("연결 실패", str(e))
            self.status_var.set("연결 실패")

    def disconnect(self):
        global is_paused
        stop_event.set()
        time.sleep(0.1)

        if self.comm['ser']:
            try:
                self.comm['ser'].close()
            except:
                pass
            self.comm['ser'] = None
        if self.comm['sock']:
            try:
                self.comm['sock'].shutdown(socket.SHUT_RDWR)
                self.comm['sock'].close()
            except:
                pass
            self.comm['sock'] = None

        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.DISABLED)
        self.btn_refresh.config(state=tk.NORMAL)
        self.port_combo.config(state="normal")
        self.baud_combo.config(state="readonly")
        self.mode_combo.config(state="readonly")

        mode = self.mode_var.get()
        if "랜 통신" in mode:
            self.op_mode_combo.config(state="disabled")
        else:
            self.op_mode_combo.config(state="readonly", values=OP_MODES_ALL)

        is_paused = False
        self.btn_pause.config(text="일시 정지")

        self.status_var.set("연결 종료")
        self.update_gui_log("연결 종료")
        self.tx_display_var.set("송신 데이터: 연결 종료")
        self.rx_display_var.set("수신 데이터: 연결 종료")

    def on_closing(self):
        self.disconnect()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AnemometerTesterApp(root)
    root.mainloop()
