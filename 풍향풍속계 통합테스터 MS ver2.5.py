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
BAUDRATES = [2400, 4800, 9600, 19200, 38400] 
COMM_FORMATS = ["WMT52 (NMEA)", "703 (Binary)", "Blue Sonic"]
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
    direction_scaled = int(direction * 20)
    speed_scaled = int(speed * 40)
    
    # <BB: Header(1), Length(1) / >H: Dir(2) Big Endian / >H: Speed(2) Big Endian
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
# 송신 스레드 (최적화 적용)
# ================================
def sender_thread(comm, app_instance):
    global current_speed, current_direction, is_paused
    
    last_ui_update_time = 0
    
    while not stop_event.is_set():
        loop_start_time = time.time()

        if is_paused:
            time.sleep(0.1)
            continue

        try:
            # GUI 변수 접근은 최소화하거나 안전하게 처리
            interval_str = app_instance.interval_var.get()
            interval = float(interval_str)
            if interval < 0.01: interval = 0.01  
        except:
            interval = DEFAULT_INTERVAL

        try:
            # 잦은 GUI 접근을 막기 위해 필요한 값만 가져옴
            op_mode = app_instance.op_mode_var.get()
            comm_fmt = app_instance.format_var.get()
            baud_rate = app_instance.baud_var.get()
        except:
            time.sleep(0.1)
            continue
        
        data_to_send = None
        msg_display = ""
        tx_status_text = ""
        
        # [데이터 생성]
        if op_mode == OP_MODE_WRITE:
            if comm['mode'] == "랜 통신":
                tx_status_text = "오류: LAN은 쓰기 모드를 지원하지 않습니다."
            else:
                if "703" in comm_fmt:
                    if baud_rate != 2400:
                        tx_status_text = "전송 불가: 703 모드는 2400bps 전용입니다."
                    else:
                        # 703 바이너리 생성
                        with lock:
                            cur_spd, cur_dir = current_speed, current_direction
                        msg_display, data_to_send = create_703_sentence(cur_dir, cur_spd)
                        tx_status_text = f"TX(703): 속도 {cur_spd:.1f}, 방향 {cur_dir}° [HEX: {msg_display}]"
                else:
                    # NMEA 생성
                    with lock:
                        cur_spd, cur_dir = current_speed, current_direction
                    msg_display = create_nmea_sentence(cur_dir, cur_spd, comm_fmt)
                    data_to_send = msg_display.encode('ascii')
                    tx_status_text = f"TX(NMEA): {msg_display.strip()}"
        
        elif op_mode == OP_MODE_READ:
            # 읽기 모드(Polling) 로직 생략 (기존 유지)
            polling_cmd = app_instance.poll_cmd_var.get().strip()
            if polling_cmd:
                 full_cmd = polling_cmd + ("\r\n" if not polling_cmd.endswith('\n') else "")
                 data_to_send = full_cmd.encode('ascii')
                 tx_status_text = f"TX(Poll): {polling_cmd}"
            else:
                 tx_status_text = "송신 대기 (수신 전용)"

        # 데이터 전송 수행
        if data_to_send:
            try:
                # [중요] 2400bps 등 저속 통신에서 write 자체가 시간이 걸리므로 Lock 최소화
                if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                    # 시리얼 버퍼가 꽉 차지 않도록만 관리 (reset은 수신부에서 처리 추천하지만 여기서도 안전장치)
                    # comm['ser'].reset_input_buffer() # 쓰기모드에선 수신버퍼 비우는게 낫지만, write 직전엔 생략 가능
                    comm['ser'].write(data_to_send)
                elif comm['mode'] == "랜 통신" and comm.get('sock'):
                    comm['sock'].sendall(data_to_send)
                    
                # [핵심 최적화]
                # 매번 update_gui_log(스크롤 텍스트)를 호출하면 GUI가 멈춤 (10초 딜레이 원인)
                # 따라서 성공 시에는 상단 라벨(update_tx_data_ui)만 업데이트함.
                app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)

            except Exception as e:
                err_msg = f"[TX ERR] {e}"
                app_instance.master.after(0, app_instance.update_gui_log, err_msg)
                if "LAN" in comm['mode']:
                    stop_event.set()
                    break
        else:
            # 보낼 데이터가 없거나 에러 텍스트인 경우 라벨 업데이트
            app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)
                
        # 인터벌 관리 (정확한 주기 유지를 위해 경과 시간 차감)
        elapsed_time = time.time() - loop_start_time
        sleep_time = interval - elapsed_time
        
        if sleep_time > 0:
            time.sleep(sleep_time)
        else:
            # 전송 시간이 인터벌보다 길어진 경우 (예: 2400bps에서 너무 빠른 전송 시도)
            # CPU 점유율 방지를 위해 최소한의 슬립
            time.sleep(0.001)

# ================================
# 수신 스레드
# ================================
def receiver_thread(comm, app_instance):
    while not stop_event.is_set():
        if is_paused:
            time.sleep(0.1)
            continue

        try:
            op_mode = app_instance.op_mode_var.get()
        except:
            time.sleep(0.1)
            continue

        # [쓰기 모드 최적화]
        # 쓰기 모드에서는 들어오는 데이터(Echo 등)를 무시해야 버퍼 오버플로우 및 렉 방지
        if op_mode == OP_MODE_WRITE:
            try:
                if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                    # in_waiting이 있으면 한 번에 싹 비움
                    n = comm['ser'].in_waiting
                    if n > 0:
                        comm['ser'].read(n) 
                elif comm['mode'] == "랜 통신" and comm.get('sock'):
                    # 넌블로킹 읽기 시도 (구현 복잡성으로 인해 패스하거나 짧은 타임아웃)
                    pass
            except:
                pass
            # 쓰기 모드에서는 수신 대기 시간을 조금 넉넉히 주어 CPU 양보
            time.sleep(0.05) 
            continue

        # [읽기 모드 - 기존 로직 유지하되 안정성 보강]
        try:
            data = b''
            source = ""
            current_fmt = app_instance.format_var.get()
            
            if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                ser = comm['ser']
                if ser.in_waiting:
                    # 데이터 파편화 방지를 위한 아주 짧은 대기
                    time.sleep(0.02) 
                    data = ser.read(ser.in_waiting)
                    source = "SER"
                else:
                    time.sleep(0.01)
            
            elif comm['mode'] == "랜 통신" and comm.get('sock'):
                try:
                    chunk = comm['sock'].recv(4096)
                    if not chunk: raise ConnectionResetError("Remote closed")
                    data = chunk
                    source = "LAN"
                except socket.timeout: 
                    pass
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[LAN ERR] {e}")
                    stop_event.set()
                    break

            if data:
                # 수신 데이터 처리 (로그는 읽기 모드에서만 찍으므로 성능 이슈 적음)
                hex_str = ' '.join(f'{b:02X}' for b in data)
                try:
                    text_str = data.decode('ascii', errors='ignore').strip()
                except:
                    text_str = "..."

                # 노이즈 필터링 및 로그
                is_noise = False
                if "703" not in current_fmt and not text_str.startswith('$') and "R000" not in text_str:
                    is_noise = True
                
                if not is_noise:
                    if "703" in current_fmt:
                        log_msg = f"RX({source}): [HEX: {hex_str}]"
                    else:
                        log_msg = f"RX({source}): {text_str}"
                    app_instance.master.after(0, app_instance.update_gui_log, log_msg)
                
                # 파싱 로직 (기존과 동일)
                parse_result = "해석 불가"
                
                # 703 파싱
                if "703" in current_fmt:
                    found_703 = False
                    data_len = len(data)
                    for i in range(data_len - 6):
                        if data[i] == HEADER_703 and data[i+1] == LENGTH_703:
                            packet = data[i:i+7]
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
                                    ang = dir_raw / 20.0
                                    parse_result = f"수신(703): 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}°"
                                    found_703 = True
                                    break 
                                except: pass
                    if not found_703 and len(data) >= 2 and data[0] == HEADER_703:
                        parse_result = "703 헤더 감지됨 (패킷 완성 대기)"

                # NMEA 파싱
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
                        # R000 파싱
                        try:
                            start_idx = data.find(b'R000:')
                            if start_idx != -1 and len(data) >= start_idx + 13:
                                payload = data[start_idx+5 : start_idx+13]
                                val1, val2 = struct.unpack('<ff', payload)
                                parse_result = f"수신(R000): 풍속: {val2:.1f} m/s, 풍향: {val1:.1f}°"
                        except: pass

                if parse_result != "해석 불가":
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
        self.master.title("풍향풍속계 통합 테스터 민쑤 VER2.5 (High Speed Optimized)")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.master.geometry("800x750") 
        self.master.resizable(True, True)

        self.comm = {'mode': MODES[0], 'ser': None, 'sock': None}
        self.sender_thread = None
        self.receiver_thread = None

        # Variables
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

        self.create_ui()
        self.update_port_list()
        self.check_my_ip() 
        self.master.after(10, self.on_mode_change)

    def check_my_ip(self):
        try:
            hostname = socket.gethostname()
            all_ips = socket.gethostbyname_ex(hostname)[2]
            valid_ips = [ip for ip in all_ips if not ip.startswith("127.")]
            if valid_ips:
                display_str = " / ".join(valid_ips)
                self.my_local_ip_var.set(display_str)
            else:
                self.my_local_ip_var.set("IP 찾기 실패 (네트워크 확인)")
        except Exception as e:
            self.my_local_ip_var.set(f"확인 불가")

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

    def create_ui(self):
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # 1. 상단 정보
        info_frame = ttk.LabelFrame(main_frame, text="실시간 데이터 상태", padding=10)
        info_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        self.lbl_rx = ttk.Label(info_frame, textvariable=self.rx_display_var, 
                                font=("Malgun Gothic", 16, "bold"), foreground="blue")
        self.lbl_rx.pack(anchor="center", pady=2)

        self.lbl_tx = ttk.Label(info_frame, textvariable=self.tx_display_var, 
                                font=("Malgun Gothic", 16, "bold"), foreground="red")
        self.lbl_tx.pack(anchor="center", pady=2)

        # 2. 통신 설정
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

        # 시리얼 프레임
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

        # 랜 프레임
        self.lan_frame = ttk.Frame(self.settings_container)
        self.lan_frame.grid(row=0, column=0, sticky="nsew")
        self.lan_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.lan_frame, text="타겟 IP:").grid(row=0, column=0, sticky="w")
        self.ip_var.set("192.168.0.2") 
        ttk.Entry(self.lan_frame, textvariable=self.ip_var).grid(row=0, column=1, sticky="ew", padx=(5, 10))
        ttk.Label(self.lan_frame, text="Port:").grid(row=0, column=2, sticky="w")
        ttk.Entry(self.lan_frame, textvariable=self.lan_port_var, width=5).grid(row=0, column=3, sticky="w")
        
        ttk.Label(self.lan_frame, text="내 PC IP:").grid(row=1, column=0, sticky="w", pady=(5,0))
        ttk.Label(self.lan_frame, textvariable=self.my_local_ip_var, foreground="blue").grid(row=1, column=1, columnspan=3, sticky="w", pady=(5,0), padx=5)

        self.btn_system_settings = ttk.Button(conn_frame, text="장치 관리자", command=self.open_system_settings)
        self.btn_system_settings.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(5, 0))

        self.btn_connect = ttk.Button(conn_frame, text="연결 하기", command=self.connect)
        self.btn_connect.grid(row=3, column=0, columnspan=2, pady=(10, 5), sticky="ew")
        self.btn_disconnect = ttk.Button(conn_frame, text="연결 종료", command=self.disconnect, state=tk.DISABLED)
        self.btn_disconnect.grid(row=4, column=0, columnspan=2, sticky="ew")

        # 3. 동작 모드 설정
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

        # [쓰기 모드 UI]
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

        # [읽기 모드 UI]
        self.read_widgets_frame = ttk.Frame(self.detail_frame)
        self.read_widgets_frame.grid(row=0, column=0, sticky="nsew")
        self.read_widgets_frame.columnconfigure(0, weight=1)
        
        ttk.Label(self.read_widgets_frame, text="[폴링 명령어 (비워두면 수신 전용)]", foreground="green").grid(row=0, column=0, sticky="w")
        
        ttk.Entry(self.read_widgets_frame, textvariable=self.poll_cmd_var).grid(row=1, column=0, sticky="ew", pady=(0, 5))
        ttk.Label(self.read_widgets_frame, text="* 자동 전송 센서는 위 칸을 비우세요.", foreground="gray", font=("Malgun Gothic", 8)).grid(row=2, column=0, sticky="w")
        ttk.Label(self.read_widgets_frame, text="* 703읽기모드는 WMT32포맷 4800속도 해야함", foreground="red", font=("Malgun Gothic", 8)).grid(row=3, column=0, sticky="w")

        self.btn_pause = ttk.Button(op_frame, text="일시 정지", command=self.toggle_pause, state=tk.DISABLED)
        self.btn_pause.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)

        # 4. 로그
        log_frame = ttk.LabelFrame(main_frame, text="3. RAW 로그 (전송데이터는 생략됨)", padding=5)
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
            s_input = float(self.speed_var.get())
            d_input = int(self.direction_var.get())
            if not (0 <= s_input <= 99):
                messagebox.showwarning("범위 초과", "풍속(0 ~ 99)")
                return 
            if not (0 <= d_input <= 359):
                messagebox.showwarning("범위 초과", "풍향(0 ~ 359)")
                return 
            with lock:
                current_speed = s_input
                current_direction = d_input
            self.sim_status_var.set(f"설정값: 풍속 {s_input} m/s, 풍향 {d_input}°")
            self.update_gui_log(f"[설정 변경] 풍속:{s_input}, 풍향:{d_input}")
        except ValueError:
            messagebox.showerror("입력 오류", "유효한 숫자 혹은 풍속,풍향 미입력 상태.")

    def toggle_pause(self):
        global is_paused
        with lock: 
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
        
        with lock:
            is_paused = False
        self.btn_pause.config(text="일시 정지")
        
        mode = self.mode_var.get()
        self.comm['mode'] = mode
        
        try:
            if "시리얼 통신" in mode:
                port = self.port_var.get()
                baud = self.baud_var.get()
                # 2400bps 등 저속에서는 timeout을 넉넉히 주거나 0으로 설정(Non-blocking)을 고려해야 함
                # 여기서는 0.1s 유지하되 스레드에서 처리
                self.comm['ser'] = serial.Serial(port, baud, timeout=0.1)
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
            try: self.comm['ser'].close() 
            except: pass
            self.comm['ser'] = None
        if self.comm['sock']:
            try: 
                self.comm['sock'].shutdown(socket.SHUT_RDWR)
                self.comm['sock'].close() 
            except: pass
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
        
        with lock:
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