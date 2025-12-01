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
LENGTH_703 = 0x06 # 703 포맷은 헤더(1) + 길이(1) + 풍속(2) + 풍향(2) + 체크섬(1) = 7바이트 (코드의 기존 LENGTH_703 0x06이므로 6바이트로 유지, 실제 데이터는 6바이트로 간주)

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
    speed_scaled = int(speed * 100)
    direction_scaled = int(direction * 20)
    # 703 포맷: [H(1)] + [L(1)] + [풍속(2, Little)] + [풍향(2, Big)]
    data_core = struct.pack('<BBH', HEADER_703, LENGTH_703, speed_scaled)
    data_core += struct.pack('>H', direction_scaled)
    
    # 체크섬 계산 (전체 바이트 합의 0x100에 대한 보수)
    byte_sum = sum(data_core)
    checksum = (0x100 - (byte_sum & 0xFF)) & 0xFF
    final_bytes = data_core + struct.pack('B', checksum)
    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes

# ================================
# 송신 스레드
# (기존 코드와 동일, 쓰기 모드만 처리)
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
        
        # 데이터 생성
        if op_mode == OP_MODE_WRITE:
            tx_status_text = f"송신 데이터: 풍속: {current_speed:.1f} m/s  풍향: {current_direction}°"

            if "703" in comm_fmt:
                msg_display, data_to_send = create_703_sentence(current_direction, current_speed)
            else:
                msg_display = create_nmea_sentence(current_direction, current_speed, comm_fmt)
                data_to_send = msg_display.encode('ascii')
        
        elif op_mode == OP_MODE_READ:
            # 읽기 모드 (폴링 커맨드 송신)
            polling_cmd = app_instance.poll_cmd_var.get()
            if polling_cmd: 
                msg_display = f"[POLL] {polling_cmd}"
                tx_status_text = f"송신 데이터: {polling_cmd}"
                full_cmd = polling_cmd
                if not full_cmd.endswith('\r') and not full_cmd.endswith('\n'):
                    full_cmd += "\r\n" 
                data_to_send = full_cmd.encode('ascii')
            else:
                data_to_send = None
                tx_status_text = "송신 데이터: (대기 중 - 폴링 없음)"

        # 데이터 전송
        if data_to_send:
            try:
                with lock: 
                    if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                        comm['ser'].write(data_to_send)
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
            if op_mode == OP_MODE_WRITE:
                app_instance.master.after(0, app_instance.update_tx_data_ui, tx_status_text)
                
        elapsed_time = time.time() - loop_start_time
        sleep_time = interval - elapsed_time
        
        if sleep_time > 0:
            time.sleep(sleep_time)

# ================================
# 수신 스레드 (읽기 모드 안정화)
# ================================
def receiver_thread(comm, app_instance):
    if 'recv_buffer' not in comm or comm['recv_buffer'] is None:
        comm['recv_buffer'] = b'' 
        
    while not stop_event.is_set():
        if is_paused:
            time.sleep(0.1)
            continue

        try:
            data = b''
            source = ""
            
            # 1. 데이터 수신
            if comm['mode'] == "시리얼 통신" and comm.get('ser'):
                ser = comm['ser']
                try:
                    if ser.in_waiting:
                        data = ser.read(ser.in_waiting)
                        source = "SER"
                    else:
                        time.sleep(0.05)
                except Exception as e:
                    app_instance.master.after(0, app_instance.update_gui_log, f"[SER ERR] {e}")
                    time.sleep(0.5)
            
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

            # 2. 데이터 처리 및 파싱 (버퍼링 로직 개선)
            if data:
                # RAW 데이터 로깅 (텍스트/HEX)
                hex_str = ' '.join(f'{b:02X}' for b in data)
                try:
                    text_str = data.decode('ascii', errors='ignore').strip()
                except:
                    text_str = "..."

                log_msg = f"RX({source}): {text_str}  [HEX: {hex_str}]"
                app_instance.master.after(0, app_instance.update_gui_log, log_msg)
                
                # 수신 버퍼에 데이터 추가
                comm['recv_buffer'] += data
                
                # 버퍼에서 메시지 단위로 추출 및 파싱 시도
                while comm['recv_buffer']:
                    buffer_len = len(comm['recv_buffer'])
                    current_data = comm['recv_buffer']
                    message = None
                    parse_result = "해석 불가"
                    parsed = False
                    
                    # 703 바이너리 처리
                    if buffer_len >= LENGTH_703 and current_data[0] == HEADER_703 and current_data[1] == LENGTH_703:
                        message = current_data[:LENGTH_703]
                        
                        # 703 체크섬 검증
                        byte_sum = sum(message[:-1])
                        checksum_expected = (0x100 - (byte_sum & 0xFF)) & 0xFF
                        checksum_received = message[-1]
                        
                        if checksum_expected == checksum_received:
                            comm['recv_buffer'] = current_data[LENGTH_703:] # 버퍼 업데이트
                            parsed = True
                            # 703 파싱
                            try:
                                _, _, spd_raw = struct.unpack('<BBH', message[:4])
                                dir_raw = struct.unpack('>H', message[4:6])[0]
                                
                                spd = spd_raw / 100.0
                                ang = dir_raw / 20.0
                                parse_result = f"수신 데이터: 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}° (703)"
                            except Exception as e:
                                parse_result = f"703 바이너리 파싱 오류: {e}"
                        else:
                            # 체크섬 불일치 -> 시작 바이트가 잘못되었거나 데이터가 깨짐
                            app_instance.master.after(0, app_instance.update_gui_log, f"[703 ERR] 체크섬 불일치. (예상:{checksum_expected:02X}, 수신:{checksum_received:02X}) 1바이트 버림.")
                            comm['recv_buffer'] = current_data[1:] # 1바이트 버리고 다음 HEADER_703 찾기
                            continue # 다음 루프로 이동하여 새로운 시작 바이트 확인
                    
                    # NMEA 처리
                    elif current_data.startswith(b'$WIMWV'):
                        nmea_end = current_data.find(b'\r\n')
                        if nmea_end != -1:
                            message = current_data[:nmea_end+2]
                            comm['recv_buffer'] = current_data[nmea_end+2:]
                            parsed = True
                            
                            # NMEA 파싱
                            try:
                                text_str_msg = message.decode('ascii', errors='ignore').strip()
                                parts = text_str_msg.split(',')
                                if len(parts) >= 5:
                                    val1 = float(parts[1]) if parts[1] else 0.0
                                    val3 = float(parts[3]) if parts[3] else 0.0
                                    
                                    # NMEA는 일반적으로 WMT52 (풍향, 속도) 포맷을 따르지만, Blue Sonic의 경우 순서가 바뀜
                                    # 읽기 모드에서는 장비의 실제 출력 포맷을 가정해야 함. 여기서는 WMT52 표준을 기본으로 함.
                                    ang, spd = val1, val3
                                        
                                    parse_result = f"수신 데이터: 풍속: {spd:.1f} m/s, 풍향: {ang:.1f}° (NMEA)"
                            except Exception as e:
                                parse_result = f"NMEA 파싱 오류: {e}"
                    
                    # R000 처리 (NMEA처럼 CR/LF 종단으로 간주)
                    elif current_data.startswith(b'R000'):
                        r000_end = current_data.find(b'\r\n')
                        if r000_end != -1:
                            message = current_data[:r000_end+2]
                            comm['recv_buffer'] = current_data[r000_end+2:]
                            parsed = True

                            # R000 파싱 (기존 코드에서 누락된 부분)
                            try:
                                # R000?에 대한 응답이 R000:float(풍향)float(풍속) 형태라고 가정하고, float 8바이트 2개로 파싱을 시도
                                # 실제 장비 프로토콜에 따라 정확히 맞춰야 함. 여기서는 예시로 float(4byte)+float(4byte)로 파싱 시도
                                payload = message[5:13] # R000: 이후 8바이트
                                if len(payload) == 8:
                                    val1, val2 = struct.unpack('<ff', payload)
                                    parse_result = f"수신 데이터: 풍속: {val2:.1f} m/s, 풍향: {val1:.1f}° (R000-Bin)"
                                else:
                                    parse_result = f"R000 응답 파싱 불가 (길이 불일치)"
                            except Exception as e:
                                parse_result = f"R000 파싱 오류: {e}"
                    
                    # 파싱 성공 또는 파싱 오류 발생 시 GUI 업데이트
                    if parsed:
                        if "해석 불가" not in parse_result and "오류" not in parse_result:
                            app_instance.master.after(0, app_instance.update_parsed_data, parse_result)
                        elif "오류" in parse_result:
                            app_instance.master.after(0, app_instance.update_gui_log, f"[PARSE ERR] {parse_result}")
                        
                        # 다음 메시지 처리를 위해 while 루프 계속 진행
                        
                    elif current_data[0] != HEADER_703 and not current_data.startswith(b'$') and not current_data.startswith(b'R'):
                        # 메시지 시작점이 아닌 쓰레기 데이터로 시작하는 경우 1바이트 버림 (Recovery)
                        comm['recv_buffer'] = current_data[1:] 
                        app_instance.master.after(0, app_instance.update_gui_log, f"[RECOVERY] 1바이트 버림: {current_data[:1].hex()}")
                    else:
                        # 미완성 메시지 (더 많은 데이터 수신 대기)
                        break 
        
        except Exception as e:
            if not stop_event.is_set():
                print(f"Recv Error: {e}")
                app_instance.master.after(0, app_instance.update_gui_log, f"[RCV ERR] Thread Error: {e}")
            time.sleep(1)

# ================================
# GUI Application (기존 코드와 동일)
# ================================
class AnemometerTesterApp:
    def __init__(self, master):
        self.master = master
        master.title("풍향풍속계 통합 테스터 MS-251120-VER2")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        master.geometry("800x750") 
        master.resizable(True, True)

        self.comm = {'mode': MODES[0], 'ser': None, 'sock': None, 'recv_buffer': b''} # recv_buffer 추가
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
        self.check_my_ip() # 시작 시 내 IP 확인
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
        
        ttk.Label(self.read_widgets_frame, text="[데이터 모니터링/폴링 활성화]", foreground="green").pack(anchor="w", fill=tk.X)
        
        r_sub = ttk.Frame(self.read_widgets_frame)
        r_sub.pack(fill=tk.X, pady=5)
        r_sub.columnconfigure(1, weight=1)
        ttk.Label(r_sub, text="폴링 명령어:").grid(row=0, column=0, sticky="w")
        ttk.Entry(r_sub, textvariable=self.poll_cmd_var).grid(row=0, column=1, sticky="ew", padx=(5, 10))


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
        
        if "랜 통신" in mode:
            self.lan_frame.tkraise() 
            self.btn_system_settings.config(state=tk.NORMAL, text="네트워크 설정")
            self.check_my_ip() 
            
            # 랜 통신은 읽기 모드(Client)만 지원
            self.op_mode_combo.config(values=OP_MODES_READ_ONLY)
            self.op_mode_var.set(OP_MODE_READ) 
        else: 
            self.serial_frame.tkraise() 
            self.btn_system_settings.config(state=tk.NORMAL, text="장치 관리자")
            self.op_mode_combo.config(values=OP_MODES_ALL)
        
        self.on_op_mode_change()

    def on_op_mode_change(self):
        mode = self.op_mode_var.get()
        if mode == OP_MODE_WRITE:
            # 쓰기 모드로 진입 시
            self.read_widgets_frame.grid_remove()
            self.write_widgets_frame.grid()
            self.format_combo.config(state="readonly")
            self.rx_display_var.set("수신 데이터: 대기 중...")
        else:
            # 읽기 모드로 진입 시
            self.write_widgets_frame.grid_remove()
            self.read_widgets_frame.grid()
            self.format_combo.config(state="disabled") # 읽기 모드 시 포맷 선택 비활성화
            self.tx_display_var.set("송신 데이터: 대기 중...")

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
            messagebox.showerror("입력 오류", "유효한 숫자를 입력하세요.")

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
        self.comm['recv_buffer'] = b'' # 연결 시 버퍼 초기화
        
        try:
            if "시리얼 통신" in mode:
                port = self.port_var.get()
                baud = self.baud_var.get()
                self.comm['ser'] = serial.Serial(port, baud, timeout=0.1)
                self.status_var.set(f"연결됨: {port}")
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
            
            # 연결 후 설정 변경 잠금
            if "시리얼" in mode:
                self.btn_refresh.config(state=tk.DISABLED)
                self.port_combo.config(state="disabled")
                self.baud_combo.config(state="disabled")
            
            self.mode_combo.config(state="disabled")
            self.op_mode_combo.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("연결 실패", str(e))
            self.status_var.set("연결 실패")

    def disconnect(self):
        global is_paused
        stop_event.set()
        time.sleep(0.2) # 스레드가 종료될 시간을 줌
        
        # 통신 객체 정리
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
        self.comm['recv_buffer'] = b''

        # GUI 상태 업데이트
        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self.btn_pause.config(state=tk.DISABLED)
        
        # 연결 해제 후 설정 변경 가능하게 복원
        self.btn_refresh.config(state=tk.NORMAL)
        self.port_combo.config(state="normal")
        self.baud_combo.config(state="readonly")
        
        self.mode_combo.config(state="readonly")
        self.op_mode_combo.config(state="readonly", values=OP_MODES_ALL)
        
        with lock:
            is_paused = False
        self.btn_pause.config(text="일시 정지")

        self.status_var.set("연결 종료")
        self.update_gui_log("연결 종료")
        self.tx_display_var.set("송신 데이터: 연결 종료")

    def on_closing(self):
        self.disconnect()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AnemometerTesterApp(root)
    root.mainloop()