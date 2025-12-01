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

# ---------------------------
# 전역 상태 변수
# ---------------------------
current_speed = 0.0
current_direction = 0
is_paused = False
lock = threading.Lock()
stop_event = threading.Event()

# --- 설정 ---
DEFAULT_INTERVAL = 1.0
BAUDRATES = [2400, 4800, 9600, 19200, 38400, 57600, 115200] 
COMM_FORMATS = ["WS703 (Binary)", "WMT52 (NMEA)", "Blue Sonic"] # 순서 변경
MODES = ["시리얼 통신", "랜 통신"]

# 동작 모드 상수
OP_MODE_WRITE = "쓰기 모드 (Simulator)"
OP_MODE_READ = "읽기 모드 (Monitor/Poller)"
OP_MODES_ALL = [OP_MODE_WRITE, OP_MODE_READ]
OP_MODES_READ_ONLY = [OP_MODE_READ] 

# 703 포맷 상수
HEADER_703 = 0x01
LENGTH_703 = 0x06

# ================================
# 데이터 생성 로직 (쓰기 모드용)
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
    # WS703 쓰기(시뮬레이터) 포맷 생성
    speed_scaled = int(speed * 100) # 쓰기 모드는 시뮬레이션이라 기존 로직 유지하되 읽기는 수정됨
    direction_scaled = int(direction * 20)
    
    # WS703 구조: [01][06][DIR_HI][DIR_LO][SPD_HI][SPD_LO][CS]
    # (사용자가 제공한 읽기 포맷에 맞추려면 쓰기 로직도 맞춰야 하지만, 현재는 읽기가 중요하므로 유지)
    data_core = struct.pack('<BBH', HEADER_703, LENGTH_703, speed_scaled)
    data_core += struct.pack('>H', direction_scaled)
    byte_sum = sum(data_core)
    checksum = (0x100 - (byte_sum & 0xFF)) & 0xFF
    final_bytes = data_core + struct.pack('B', checksum)
    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes

# ================================
# 송신 스레드 (Hex 기능 추가됨)
# ================================
def sender_thread(comm, app_instance):
    global current_speed, current_direction, is_paused
    
    while not stop_event.is_set():
        loop_start_time = time.time()

        if is_paused:
            time.sleep(0.1)
            continue

        try:
            interval = float(app_instance.interval_var.get())
            if interval < 0.1: interval = 0.1
        except:
            interval = DEFAULT_INTERVAL

        op_mode = app_instance.op_mode_var.get()
        comm_fmt = app_instance.format_var.get()
        
        data_to_send = None
        msg_display = ""
        tx_status_text = ""
        
        # [1] 쓰기 모드 (Simulator)
        if op_mode == OP_MODE_WRITE:
            tx_status_text = f"송신 데이터: 풍속: {current_speed:.1f} m/s  풍향: {current_direction}°"
            if "703" in comm_fmt:
                msg_display, data_to_send = create_703_sentence(current_direction, current_speed)
            else:
                msg_display = create_nmea_sentence(current_direction, current_speed, comm_fmt)
                data_to_send = msg_display.encode('ascii')
        
        # [2] 읽기 모드 (Poller)
        elif op_mode == OP_MODE_READ:
            polling_cmd = app_instance.poll_cmd_var.get().strip()
            
            if polling_cmd: 
                # Hex 체크박스 확인
                is_hex = app_instance.poll_hex_var.get()
                
                if is_hex:
                    # HEX 문자열 처리 (예: "01 03 00" -> bytes)
                    try:
                        # 공백 제거 후 2글자씩 끊어서 변환
                        clean_hex = polling_cmd.replace(" ", "").replace(":", "")
                        data_to_send = bytes.fromhex(clean_hex)
                        msg_display = f"[POLL HEX] {data_to_send.hex().upper()}"
                        tx_status_text = f"송신(HEX): {data_to_send.hex().upper()}"
                    except ValueError:
                        msg_display = "[ERR] Invalid Hex String"
                        tx_status_text = "송신 오류: 올바르지 않은 HEX 포맷"
                        data_to_send = None
                else:
                    # 기존 텍스트 방식
                    msg_display = f"[POLL] {polling_cmd}"
                    tx_status_text = f"송신(ASCII): {polling_cmd}"
                    full_cmd = polling_cmd
                    if not full_cmd.endswith('\r') and not full_cmd.endswith('\n'):
                        full_cmd += "\r\n" 
                    data_to_send = full_cmd.encode('ascii')
            else:
                # 폴링 명령어가 비어있으면 전송하지 않음 (Passive 수신 대기)
                data_to_send = None
                tx_status_text = "송신 대기 (수신 전용)"

        # 실제 전송부
        if data_to_send:
            try:
                with lock: 
                    if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                        comm['ser'].write(data_to_send)
                        comm['ser'].flush() 
                        app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                        app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

                    elif comm['mode'] == "랜 통신" and comm.get('sock'):
                        comm['sock'].sendall(data_to_send)
                        app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                        app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

            except Exception as e:
                app_instance.master.after(0, app_instance.update_gui_log, f"[TX ERR] {e}")
                if "LAN" in comm['mode']:
                    stop_event.set()
                    break
        else:
            if op_mode == OP_MODE_WRITE or (op_mode == OP_MODE_READ and not polling_cmd):
                app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)
                
        elapsed_time = time.time() - loop_start_time
        sleep_time = interval - elapsed_time
        if sleep_time > 0:
            time.sleep(sleep_time)

# ================================
# 수신 스레드 (버퍼링 & WS703 파싱)
# ================================
def receiver_thread(comm, app_instance):
    rx_buffer = b'' 
    
    while not stop_event.is_set():
        if is_paused:
            time.sleep(0.1)
            continue

        try:
            # 1. 데이터 수신
            received_chunk = b''
            source = ""
            
            if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                ser = comm['ser']
                try:
                    if ser.in_waiting > 0:
                        received_chunk = ser.read(ser.in_waiting)
                        source = "SER"
                    else:
                        time.sleep(0.01)
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[SER ERR] {e}")
                    time.sleep(0.5)
            
            elif comm['mode'] == "랜 통신" and comm.get('sock'):
                sock = comm['sock']
                try:
                    chunk = sock.recv(4096)
                    if not chunk: 
                        raise ConnectionResetError("Remote closed")
                    received_chunk = chunk
                    source = "LAN"
                except socket.timeout:
                    pass
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[LAN ERR] {e}")
                    stop_event.set()
                    break

            if received_chunk:
                rx_buffer += received_chunk
                # RX_RAW 로그는 디버깅의 핵심이므로 무조건 출력
                hex_preview = ' '.join(f'{b:02X}' for b in received_chunk[:20])
                if len(received_chunk) > 20: hex_preview += "..."
                app_instance.master.after(0, app_instance.update_gui_log, f"RX_RAW: {hex_preview}")

            if not rx_buffer:
                continue

            # 2. 파싱 로직
            # [A] WS703 바이너리 (헤더 01 06)
            while True:
                idx_703 = rx_buffer.find(b'\x01\x06')
                idx_nmea = rx_buffer.find(b'$')
                
                if idx_703 == -1 and idx_nmea == -1:
                    break

                # CASE 1: 703 헤더 발견
                if idx_703 != -1 and (idx_nmea == -1 or idx_703 < idx_nmea):
                    # 길이 확인: 7바이트
                    if len(rx_buffer) >= idx_703 + 7:
                        packet = rx_buffer[idx_703 : idx_703 + 7]
                        
                        # 체크섬 검증 (XOR 0~5 ^ 0x33)
                        calc_cs = 0
                        for b in packet[:6]:
                            calc_cs ^= b
                        calc_cs ^= 0x33
                        
                        recv_cs = packet[6]

                        if calc_cs == recv_cs:
                            # 파싱 성공
                            dir_raw = (packet[2] << 8) | packet[3] # Big Endian
                            spd_raw = (packet[4] << 8) | packet[5] # Big Endian
                            
                            real_spd = spd_raw / 40.0  # WS703 공식 적용
                            real_dir = dir_raw / 20.0  # 기존 추정치 적용
                            
                            res_msg = f"수신 데이터: 풍속: {real_spd:.1f} m/s, 풍향: {real_dir:.1f}° (WS703)"
                            app_instance.master.after(0, app_instance.update_parsed_data, res_msg)
                            app_instance.master.after(0, app_instance.update_gui_log, f"[OK] WS703: {real_spd}m/s, {real_dir}deg")
                            
                            rx_buffer = rx_buffer[idx_703 + 7:]
                            continue
                        else:
                            app_instance.master.after(0, app_instance.update_gui_log, f"[Err] CS Fail (Calc:{calc_cs:02X} != Recv:{recv_cs:02X})")
                            rx_buffer = rx_buffer[idx_703 + 1:] 
                    else:
                        break # 데이터 부족

                # CASE 2: NMEA 헤더 발견
                elif idx_nmea != -1:
                    if b'\n' in rx_buffer[idx_nmea:]:
                        line_end = rx_buffer.find(b'\n', idx_nmea)
                        line_bytes = rx_buffer[idx_nmea : line_end+1]
                        
                        try:
                            text_str = line_bytes.decode('ascii', errors='ignore').strip()
                            if text_str.startswith('$WIMWV'):
                                parts = text_str.split(',')
                                if len(parts) >= 5:
                                    val1 = float(parts[1]) if parts[1] else 0.0
                                    val3 = float(parts[3]) if parts[3] else 0.0
                                    
                                    fmt = app_instance.format_var.get()
                                    if "Blue Sonic" in fmt: 
                                        spd, ang = val1, val3
                                    else:
                                        ang, spd = val1, val3
                                        
                                    res_msg = f"수신 데이터: 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}° (NMEA)"
                                    app_instance.master.after(0, app_instance.update_parsed_data, res_msg)
                                    app_instance.master.after(0, app_instance.update_gui_log, f"[OK] NMEA: {text_str}")
                            
                            elif "R000" in text_str:
                                res_msg = f"수신 데이터: {text_str} (Text)"
                                app_instance.master.after(0, app_instance.update_parsed_data, res_msg)

                        except Exception as e:
                             pass

                        rx_buffer = rx_buffer[line_end + 1:]
                        continue
                    else:
                        break
            
            # 버퍼 초기화
            if len(rx_buffer) > 2048:
                rx_buffer = b''
                app_instance.master.after(0, app_instance.update_gui_log, "[System] 버퍼 초기화")

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
        master.title("풍향풍속계 통합 테스터 (WS703 Fix + Hex Poll)")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        master.geometry("800x800") 
        master.resizable(True, True)

        self.comm = {'mode': MODES[0], 'ser': None, 'sock': None}
        self.sender_thread = None
        self.receiver_thread = None

        # Variables
        self.op_mode_var = tk.StringVar(value=OP_MODE_WRITE)
        self.mode_var = tk.StringVar(value=MODES[0])
        self.format_var = tk.StringVar(value=COMM_FORMATS[0]) # Default WS703
        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=9600) # Default 9600으로 변경 (일반적 센서)
        self.ip_var = tk.StringVar(value="192.168.0.2")
        self.lan_port_var = tk.IntVar(value=4000)
        self.interval_var = tk.StringVar(value="1.0")
        
        self.poll_cmd_var = tk.StringVar(value="R000?")
        self.poll_hex_var = tk.BooleanVar(value=False) # Hex 송신 여부
        
        self.speed_var = tk.StringVar(value="0.0")
        self.direction_var = tk.StringVar(value="0")
        
        self.my_local_ip_var = tk.StringVar(value="확인 중...") 
        self.sim_status_var = tk.StringVar(value="현재 송신 설정값: 설정 필요") 
        self.status_var = tk.StringVar(value="대기 중")
        self.rx_display_var = tk.StringVar(value="수신 데이터: 대기 중...") 
        self.tx_display_var = tk.StringVar(value="송신 데이터: 대기 중...")

        self.create_ui()
        self.update_port_list()
        self.check_my_ip() 
        self.master.after(10, self.on_mode_change)

    def check_my_ip(self):
        try:
            hostname = socket.gethostname()
            all_ips = socket.gethostbyname_ex(hostname)[2]
            valid_ips = [ip for ip in all_ips if not ip.startswith("127.")]
            self.my_local_ip_var.set(" / ".join(valid_ips) if valid_ips else "IP 찾기 실패")
        except:
            self.my_local_ip_var.set(f"확인 불가")

    def open_system_settings(self):
        mode = self.mode_var.get()
        try:
            cmd = 'ncpa.cpl' if "랜" in mode else 'devmgmt.msc'
            if 'win' in sys.platform: subprocess.Popen(cmd, shell=True)
        except: pass

    def create_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # 1. 상단 정보
        info_frame = ttk.LabelFrame(main_frame, text="실시간 데이터 상태", padding=10)
        info_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        ttk.Label(info_frame, textvariable=self.rx_display_var, font=("Malgun Gothic", 16, "bold"), foreground="blue").pack(anchor="center", pady=2)
        ttk.Label(info_frame, textvariable=self.tx_display_var, font=("Malgun Gothic", 16, "bold"), foreground="red").pack(anchor="center", pady=2)

        # 2. 통신 설정
        conn_frame = ttk.LabelFrame(main_frame, text="1. 통신 연결 설정", padding=10)
        conn_frame.grid(row=1, column=0, padx=5, sticky="nsew")
        conn_frame.columnconfigure(0, weight=1)

        mode_frame = ttk.Frame(conn_frame)
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        mode_frame.columnconfigure(1, weight=1)
        ttk.Label(mode_frame, text="통신 방식:").grid(row=0, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(mode_frame, textvariable=self.mode_var, values=MODES, state="readonly")
        self.mode_combo.grid(row=0, column=1, sticky="ew", padx=5)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_mode_change())

        self.settings_container = ttk.Frame(conn_frame)
        self.settings_container.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        self.settings_container.columnconfigure(0, weight=1)

        # Serial UI
        self.serial_frame = ttk.Frame(self.settings_container)
        self.serial_frame.grid(row=0, column=0, sticky="nsew")
        self.serial_frame.columnconfigure(1, weight=1)
        ttk.Label(self.serial_frame, text="Port:").grid(row=0, column=0, sticky="w")
        self.port_combo = ttk.Combobox(self.serial_frame, textvariable=self.port_var, width=8)
        self.port_combo.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(self.serial_frame, text="R", command=self.update_port_list, width=3).grid(row=0, column=2, padx=5)
        ttk.Label(self.serial_frame, text="Baud:").grid(row=0, column=3, sticky="w")
        self.baud_combo = ttk.Combobox(self.serial_frame, textvariable=self.baud_var, values=BAUDRATES, width=7, state="readonly")
        self.baud_combo.grid(row=0, column=4, sticky="w")

        # LAN UI
        self.lan_frame = ttk.Frame(self.settings_container)
        self.lan_frame.grid(row=0, column=0, sticky="nsew")
        self.lan_frame.columnconfigure(1, weight=1)
        ttk.Label(self.lan_frame, text="IP:").grid(row=0, column=0)
        ttk.Entry(self.lan_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Label(self.lan_frame, text="Port:").grid(row=0, column=2)
        ttk.Entry(self.lan_frame, textvariable=self.lan_port_var, width=5).grid(row=0, column=3)

        self.btn_system_settings = ttk.Button(conn_frame, text="장치 관리자", command=self.open_system_settings)
        self.btn_system_settings.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)
        self.btn_connect = ttk.Button(conn_frame, text="연결 하기", command=self.connect)
        self.btn_connect.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        self.btn_disconnect = ttk.Button(conn_frame, text="연결 종료", command=self.disconnect, state=tk.DISABLED)
        self.btn_disconnect.grid(row=4, column=0, columnspan=2, sticky="ew")

        # 3. 동작 모드
        op_frame = ttk.LabelFrame(main_frame, text="2. 동작 모드 설정", padding=10)
        op_frame.grid(row=1, column=1, padx=5, sticky="nsew")
        op_frame.columnconfigure(1, weight=1)

        ttk.Label(op_frame, text="동작 모드:").grid(row=0, column=0, sticky="w", pady=5)
        self.op_mode_combo = ttk.Combobox(op_frame, textvariable=self.op_mode_var, values=OP_MODES_ALL, state="readonly")
        self.op_mode_combo.grid(row=0, column=1, sticky="ew", padx=5)
        self.op_mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_op_mode_change())

        ttk.Label(op_frame, text="데이터 포맷:").grid(row=1, column=0, sticky="w", pady=5)
        self.format_combo = ttk.Combobox(op_frame, textvariable=self.format_var, values=COMM_FORMATS, state="readonly")
        self.format_combo.grid(row=1, column=1, sticky="ew", padx=5)

        ttk.Label(op_frame, text="전송 주기(s):").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(op_frame, textvariable=self.interval_var, width=10).grid(row=2, column=1, sticky="w", padx=5)

        self.detail_frame = ttk.Frame(op_frame, height=120)
        self.detail_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")
        self.detail_frame.grid_propagate(False)
        self.detail_frame.columnconfigure(0, weight=1)

        # [쓰기 모드 UI]
        self.write_widgets_frame = ttk.Frame(self.detail_frame)
        self.write_widgets_frame.grid(row=0, column=0, sticky="nsew")
        self.write_widgets_frame.columnconfigure(0, weight=1)
        ttk.Label(self.write_widgets_frame, text="[시뮬레이션 값]", foreground="brown").pack(anchor="w")
        w_sub = ttk.Frame(self.write_widgets_frame)
        w_sub.pack(fill=tk.X, pady=5)
        ttk.Label(w_sub, text="속도:").pack(side=tk.LEFT)
        ttk.Entry(w_sub, textvariable=self.speed_var, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Label(w_sub, text="방향:").pack(side=tk.LEFT)
        ttk.Entry(w_sub, textvariable=self.direction_var, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Button(w_sub, text="적용", command=self.apply_values, width=5).pack(side=tk.LEFT)
        ttk.Label(self.write_widgets_frame, textvariable=self.sim_status_var, foreground="gray", font=("", 9)).pack(pady=5)

        # [읽기 모드 UI - 수정됨]
        self.read_widgets_frame = ttk.Frame(self.detail_frame)
        self.read_widgets_frame.grid(row=0, column=0, sticky="nsew")
        self.read_widgets_frame.columnconfigure(1, weight=1)
        ttk.Label(self.read_widgets_frame, text="[폴링 커맨드 설정]", foreground="green").grid(row=0, column=0, columnspan=3, sticky="w")
        
        ttk.Label(self.read_widgets_frame, text="CMD:").grid(row=1, column=0, sticky="w")
        ttk.Entry(self.read_widgets_frame, textvariable=self.poll_cmd_var).grid(row=1, column=1, sticky="ew", padx=5)
        
        # Hex 체크박스
        ttk.Checkbutton(self.read_widgets_frame, text="Hex전송", variable=self.poll_hex_var).grid(row=1, column=2, sticky="w")
        
        ttk.Label(self.read_widgets_frame, text="※ 자동수신(Active) 장비면 CMD를 비우세요.", font=("", 8), foreground="gray").grid(row=2, column=0, columnspan=3, sticky="w", pady=5)

        self.btn_pause = ttk.Button(op_frame, text="일시 정지", command=self.toggle_pause, state=tk.DISABLED)
        self.btn_pause.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)

        # 4. 로그
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
        if ports: self.port_var.set(ports[0].device)

    def on_mode_change(self):
        mode = self.mode_var.get()
        if "랜" in mode:
            self.lan_frame.tkraise()
            self.btn_system_settings.config(text="네트워크 설정")
            self.check_my_ip()
            self.op_mode_combo.config(values=OP_MODES_READ_ONLY)
            self.op_mode_var.set(OP_MODE_READ)
        else:
            self.serial_frame.tkraise()
            self.btn_system_settings.config(text="장치 관리자")
            self.op_mode_combo.config(values=OP_MODES_ALL)
        self.on_op_mode_change()

    def on_op_mode_change(self):
        if self.op_mode_var.get() == OP_MODE_WRITE:
            self.read_widgets_frame.grid_remove()
            self.write_widgets_frame.grid()
            self.format_combo.config(state="readonly")
            self.rx_display_var.set("수신 데이터: 대기 중...")
        else:
            self.write_widgets_frame.grid_remove()
            self.read_widgets_frame.grid()
            self.format_combo.config(state="disabled")
            self.tx_display_var.set("송신 데이터: 대기 중...")

    def apply_values(self):
        try:
            s, d = float(self.speed_var.get()), int(self.direction_var.get())
            with lock: current_speed, current_direction = s, d
            self.sim_status_var.set(f"설정값: {s} m/s, {d}°")
            self.update_gui_log(f"[설정 변경] {s}m/s, {d}°")
        except: messagebox.showerror("오류", "숫자만 입력하세요.")

    def toggle_pause(self):
        global is_paused
        with lock: is_paused = not is_paused
        self.btn_pause.config(text="전송 재개" if is_paused else "일시 정지")
        self.update_gui_log("!!! 일시 정지 !!!" if is_paused else "!!! 동작 재개 !!!")

    def update_gui_log(self, msg):
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)

    def update_parsed_data(self, msg): self.rx_display_var.set(msg)
    def update_tx_data_ui(self, msg): self.tx_display_var.set(msg)

    def connect(self):
        global stop_event, is_paused
        stop_event.clear()
        with lock: is_paused = False
        self.btn_pause.config(text="일시 정지")
        
        mode = self.mode_var.get()
        self.comm['mode'] = mode
        try:
            if "시리얼" in mode:
                self.comm['ser'] = serial.Serial(self.port_var.get(), self.baud_var.get(), timeout=0.1)
                self.status_var.set(f"연결됨: {self.port_var.get()}")
            else:
                sock = socket.create_connection((self.ip_var.get(), int(self.lan_port_var.get())), timeout=3.0)
                sock.settimeout(0.1)
                self.comm['sock'] = sock
                self.status_var.set(f"연결됨: LAN")

            self.sender_thread = threading.Thread(target=sender_thread, args=(self.comm, self), daemon=True)
            self.receiver_thread = threading.Thread(target=receiver_thread, args=(self.comm, self), daemon=True)
            self.sender_thread.start()
            self.receiver_thread.start()

            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
            self.btn_pause.config(state=tk.NORMAL)
            if "시리얼" in mode:
                self.port_combo.config(state="disabled")
                self.baud_combo.config(state="disabled")
            self.mode_combo.config(state="disabled")
            self.op_mode_combo.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("연결 실패", str(e))
            self.status_var.set("연결 실패")

    def disconnect(self):
        stop_event.set()
        time.sleep(0.1)
        if self.comm['ser']: 
            try: self.comm['ser'].close()
            except: pass
        if self.comm['sock']: 
            try: self.comm['sock'].close()
            except: pass
        self.comm['ser'], self.comm['sock'] = None, None
        
        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.DISABLED)
        self.port_combo.config(state="normal")
        self.baud_combo.config(state="readonly")
        self.mode_combo.config(state="readonly")
        self.op_mode_combo.config(state="readonly", values=OP_MODES_ALL)
        self.status_var.set("연결 종료")
        self.update_gui_log("연결 종료")

    def on_closing(self):
        self.disconnect()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AnemometerTesterApp(root)
    root.mainloop()