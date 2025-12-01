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
BAUDRATES = [2400, 4800, 9600, 19200, 38400, 115200]
COMM_FORMATS = ["WMT52 (NMEA)", "703 (Binary)", "Blue Sonic"]
MODES = ["SERIAL MODE", "LAN MODE"]
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
    speed_scaled = int(speed * 100)
    direction_scaled = int(direction * 20)
    data_core = struct.pack('<BBH', HEADER_703, LENGTH_703, speed_scaled)
    data_core += struct.pack('>H', direction_scaled)
    byte_sum = sum(data_core)
    checksum = (0x100 - (byte_sum & 0xFF)) & 0xFF
    final_bytes = data_core + struct.pack('B', checksum)
    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes

# ================================
# 송신 스레드
# ================================
def sender_thread(comm, app_instance):
    global current_speed, current_direction, is_paused
    
    while not stop_event.is_set():
        loop_start = time.time()
        
        try:
            interval = float(app_instance.interval_var.get())
            if interval < 0.1: interval = 0.1
        except:
            interval = 1.0

        with lock:
            op_mode = app_instance.op_mode_var.get()
            comm_fmt = app_instance.format_var.get()
            polling_cmd = app_instance.poll_cmd_var.get()

            data_to_send = None
            msg_display = ""
            
            if not is_paused:
                # [1] 쓰기 모드 (LAN 모드에서는 진입 불가하도록 GUI에서 막음)
                if op_mode == OP_MODE_WRITE:
                    if "703" in comm_fmt:
                        msg_display, data_to_send = create_703_sentence(current_direction, current_speed)
                    else:
                        msg_display = create_nmea_sentence(current_direction, current_speed, comm_fmt)
                        data_to_send = msg_display.encode('ascii')
                
                # [2] 읽기 모드 (Polling)
                elif op_mode == OP_MODE_READ:
                    if polling_cmd: 
                        msg_display = f"[POLL] {polling_cmd}"
                        full_cmd = polling_cmd
                        # 명령어 끝에 엔터가 없으면 추가 (장비 호환성)
                        if not full_cmd.endswith('\r') and not full_cmd.endswith('\n'):
                            full_cmd += "\r\n" 
                        data_to_send = full_cmd.encode('ascii')
                    else:
                        data_to_send = None

                if data_to_send:
                    try:
                        if comm['mode'] == "SERIAL MODE" and comm.get('ser'):
                            comm['ser'].write(data_to_send)
                            app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                        elif comm['mode'] == "LAN MODE" and comm.get('sock'):
                            comm['sock'].sendall(data_to_send)
                            app_instance.master.after(0, app_instance.update_gui_log, f"TX: {msg_display.strip()}")
                    except Exception as e:
                        app_instance.master.after(0, app_instance.update_gui_log, f"[TX ERR] {e}")
                        if "LAN" in comm['mode']:
                            stop_event.set()
                            break

        elapsed = time.time() - loop_start
        time.sleep(max(0, interval - elapsed))

# ================================
# 수신 스레드 (파싱 로직 추가됨)
# ================================
def receiver_thread(comm, app_instance):
    while not stop_event.is_set():
        try:
            data = b''
            source = ""
            
            # 1. 데이터 수신
            if comm['mode'] == "SERIAL MODE" and comm.get('ser'):
                ser = comm['ser']
                if ser.in_waiting:
                    data = ser.read(ser.in_waiting)
                    source = "SER"
                else:
                    time.sleep(0.05)
            
            elif comm['mode'] == "LAN MODE" and comm.get('sock'):
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

            # 2. 데이터 처리 및 파싱
            if data:
                hex_str = ' '.join(f'{b:02X}' for b in data)
                try:
                    text_str = data.decode('ascii', errors='ignore').strip()
                except:
                    text_str = "..."

                # GUI 로그에 RAW 데이터 출력
                log_msg = f"RX({source}): {text_str}  [HEX: {hex_str}]"
                app_instance.master.after(0, app_instance.update_gui_log, log_msg)
                
                # -------------------------------------------------
                # [추가] 데이터 파싱 로직 (해석하여 10진수로 표시)
                # -------------------------------------------------
                parse_result = "해석 불가"
                
                # Case A: NMEA 표준 ($WIMWV)
                if b"$WIMWV" in data:
                    try:
                        # 예: $WIMWV,123,R,10.5,M,A*CS
                        parts = text_str.split(',')
                        if len(parts) >= 5:
                            # NMEA 포맷에 따라 인덱스가 다를 수 있으니 확인 필요
                            # 보통: $WIMWV,풍향,R,풍속,M,A... 또는 $WIMWV,풍속,R,풍향,M,A... (Blue Sonic)
                            # 여기서는 일반적인 WMT52 ($WIMWV,Dir,R,Speed,M,A) 기준으로 시도
                            
                            # 값이 숫자인지 확인하여 파싱
                            val1 = float(parts[1]) if parts[1] else 0.0
                            val3 = float(parts[3]) if parts[3] else 0.0
                            
                            # 헤더 포맷 유추 (Blue Sonic은 Speed가 먼저 옴)
                            if "Blue Sonic" in app_instance.format_var.get(): 
                                spd, ang = val1, val3
                            else:
                                ang, spd = val1, val3
                                
                            parse_result = f"풍속: {spd:.1f} m/s, 풍향: {ang:.1f}° (NMEA)"
                    except:
                        parse_result = "NMEA 파싱 오류"

                # Case B: C코드 장비 바이너리 응답 (R000:...)
                elif data.startswith(b'R000:'):
                    # 데이터 구조: "R000:" (5byte) + float(4byte) + float(4byte)
                    if len(data) >= 13:
                        try:
                            payload = data[5:13] # 8 bytes
                            # C코드가 STM32(Little Endian)라고 가정하고 float 2개 언패킹
                            val1, val2 = struct.unpack('<ff', payload)
                            # C코드: fd1=Direct, fd2=Speed
                            parse_result = f"풍속: {val2:.2f} m/s, 풍향: {val1:.1f}° (R000)"
                        except:
                            parse_result = "R000 바이너리 파싱 오류"

                # Case C: 703 프로토콜
                elif len(data) == 6 and data[0] == HEADER_703:
                    try:
                        # <BBH (Header, Len, Speed*100)
                        _, _, spd_raw = struct.unpack('<BBH', data[:4])
                        # >H (Dir*20) - Big Endian
                        dir_raw = struct.unpack('>H', data[4:6])[0]
                        
                        spd = spd_raw / 100.0
                        ang = dir_raw / 20.0
                        parse_result = f"풍속: {spd:.2f} m/s, 풍향: {ang:.1f}° (703)"
                    except:
                        pass

                # 파싱된 결과를 GUI 상단에 업데이트
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
        master.title("풍향풍속계 통합 테스터 v3.0")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.comm = {'mode': MODES[0], 'ser': None, 'sock': None}
        self.sender_thread = None
        self.receiver_thread = None

        # Variables
        self.op_mode_var = tk.StringVar(value=OP_MODE_WRITE)
        self.mode_var = tk.StringVar(value=MODES[0])
        self.format_var = tk.StringVar(value=COMM_FORMATS[0])
        
        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=9600)
        
        self.ip_var = tk.StringVar(value="192.168.0.2")
        self.lan_port_var = tk.IntVar(value=4000)
        
        self.interval_var = tk.StringVar(value="1.0")
        self.poll_cmd_var = tk.StringVar(value="R000?")
        
        self.speed_var = tk.StringVar(value="0.0")
        self.direction_var = tk.StringVar(value="0")
        
        self.status_var = tk.StringVar(value="대기 중")
        self.parsed_data_var = tk.StringVar(value="수신 데이터: 대기 중...") # 파싱 결과 표시용

        self.create_ui()
        self.update_port_list()
        self.on_mode_change() # 초기 모드 설정 적용

    def create_ui(self):
        # 메인 레이아웃
        main_frame = ttk.Frame(self.master, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. 상단 정보 표시 (파싱 결과)
        info_frame = ttk.LabelFrame(main_frame, text="실시간 수신 데이터 해석", padding=10)
        info_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Label(info_frame, textvariable=self.parsed_data_var, font=("Malgun Gothic", 14, "bold"), foreground="blue").pack()

        # 2. 통신 설정
        conn_frame = ttk.LabelFrame(main_frame, text="1. 통신 연결 설정", padding=10)
        conn_frame.grid(row=1, column=0, padx=5, sticky="nsew")

        ttk.Label(conn_frame, text="통신 방식:").grid(row=0, column=0, sticky="w")
        self.mode_combo = ttk.Combobox(conn_frame, textvariable=self.mode_var, values=MODES, state="readonly", width=15)
        self.mode_combo.grid(row=0, column=1, pady=5)
        self.mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_mode_change())

        # 시리얼 UI
        self.serial_frame = ttk.Frame(conn_frame)
        self.serial_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        ttk.Label(self.serial_frame, text="Port:").pack(side=tk.LEFT)
        self.port_combo = ttk.Combobox(self.serial_frame, textvariable=self.port_var, width=10)
        self.port_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(self.serial_frame, text="R", width=2, command=self.update_port_list).pack(side=tk.LEFT)
        ttk.Label(self.serial_frame, text=" Baud:").pack(side=tk.LEFT)
        ttk.Combobox(self.serial_frame, textvariable=self.baud_var, values=BAUDRATES, width=7).pack(side=tk.LEFT)

        # LAN UI
        self.lan_frame = ttk.Frame(conn_frame)
        self.lan_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        ttk.Label(self.lan_frame, text="IP:").pack(side=tk.LEFT)
        ttk.Entry(self.lan_frame, textvariable=self.ip_var, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.lan_frame, text="Port:").pack(side=tk.LEFT)
        ttk.Entry(self.lan_frame, textvariable=self.lan_port_var, width=5).pack(side=tk.LEFT)

        self.btn_connect = ttk.Button(conn_frame, text="연결 하기", command=self.connect)
        self.btn_connect.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")
        self.btn_disconnect = ttk.Button(conn_frame, text="연결 종료", command=self.disconnect, state=tk.DISABLED)
        self.btn_disconnect.grid(row=4, column=0, columnspan=2, sticky="ew")

        # 3. 동작 모드 설정
        op_frame = ttk.LabelFrame(main_frame, text="2. 동작 모드 설정", padding=10)
        op_frame.grid(row=1, column=1, padx=5, sticky="nsew")

        ttk.Label(op_frame, text="동작 모드:").grid(row=0, column=0, sticky="w")
        # 모드 콤보박스 (값은 on_mode_change에서 동적으로 변경됨)
        self.op_mode_combo = ttk.Combobox(op_frame, textvariable=self.op_mode_var, state="readonly", width=23)
        self.op_mode_combo.grid(row=0, column=1, pady=5)
        self.op_mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_op_mode_change())

        ttk.Label(op_frame, text="데이터 포맷:").grid(row=1, column=0, sticky="w")
        self.format_combo = ttk.Combobox(op_frame, textvariable=self.format_var, values=COMM_FORMATS, state="readonly", width=23)
        self.format_combo.grid(row=1, column=1, pady=5)

        ttk.Label(op_frame, text="전송 주기(초):").grid(row=2, column=0, sticky="w")
        ttk.Entry(op_frame, textvariable=self.interval_var, width=10).grid(row=2, column=1, sticky="w", pady=5)

        # 상세 설정 프레임 (쓰기 vs 읽기)
        self.detail_frame = ttk.Frame(op_frame)
        self.detail_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky="ew")

        # [쓰기 모드 UI]
        self.write_widgets_frame = ttk.Frame(self.detail_frame)
        ttk.Label(self.write_widgets_frame, text="[시뮬레이션 값 송신]", foreground="brown").pack(anchor="w")
        w_sub = ttk.Frame(self.write_widgets_frame)
        w_sub.pack(fill=tk.X)
        ttk.Label(w_sub, text="풍속:").pack(side=tk.LEFT)
        ttk.Entry(w_sub, textvariable=self.speed_var, width=6).pack(side=tk.LEFT, padx=5)
        ttk.Label(w_sub, text="풍향:").pack(side=tk.LEFT)
        ttk.Entry(w_sub, textvariable=self.direction_var, width=6).pack(side=tk.LEFT, padx=5)
        ttk.Button(w_sub, text="적용", width=5, command=self.apply_values).pack(side=tk.LEFT)

        # [읽기 모드 UI]
        self.read_widgets_frame = ttk.Frame(self.detail_frame)
        ttk.Label(self.read_widgets_frame, text="[데이터 요청 (Polling)]", foreground="green").pack(anchor="w")
        r_sub = ttk.Frame(self.read_widgets_frame)
        r_sub.pack(fill=tk.X)
        ttk.Label(r_sub, text="CMD:").pack(side=tk.LEFT)
        ttk.Entry(r_sub, textvariable=self.poll_cmd_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Label(r_sub, text="(예: R000?)").pack(side=tk.LEFT)

        self.btn_pause = ttk.Button(op_frame, text="일시 정지", command=self.toggle_pause, state=tk.DISABLED)
        self.btn_pause.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)

        # 4. 로그
        log_frame = ttk.LabelFrame(main_frame, text="3. RAW 로그", padding=5)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=5)
        
        self.log_text = tk.Text(log_frame, height=8, width=60, font=("Consolas", 9))
        scr = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scr.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scr.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Button(log_frame, text="로그 지우기", command=lambda: self.log_text.delete(1.0, tk.END)).pack(anchor="e")

        # 상태바
        self.lbl_status = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.lbl_status.pack(side=tk.BOTTOM, fill=tk.X)

    def update_port_list(self):
        ports = list_ports.comports()
        self.port_combo['values'] = [p.device for p in ports]
        if ports: self.port_var.set(ports[0].device)

    # ----------------------------------------------------------
    # [핵심 수정 1] LAN 모드일 때 동작 모드를 '읽기'로 제한하는 로직
    # ----------------------------------------------------------
    def on_mode_change(self):
        mode = self.mode_var.get()
        
        if "LAN" in mode:
            # 1. UI 전환
            self.serial_frame.grid_remove()
            self.lan_frame.grid()
            
            # 2. 동작 모드 제한 (읽기 전용)
            self.op_mode_combo.config(values=OP_MODES_READ_ONLY)
            self.op_mode_var.set(OP_MODE_READ) # 강제로 읽기 모드로 변경
            self.on_op_mode_change() # UI 갱신 트리거

        else: # SERIAL
            # 1. UI 전환
            self.lan_frame.grid_remove()
            self.serial_frame.grid()
            
            # 2. 동작 모드 전체 허용
            self.op_mode_combo.config(values=OP_MODES_ALL)
            # 모드를 변경하진 않고 유지하되, UI 갱신
            self.on_op_mode_change()

    def on_op_mode_change(self):
        mode = self.op_mode_var.get()
        
        # 상세 설정 프레임 교체
        self.write_widgets_frame.pack_forget()
        self.read_widgets_frame.pack_forget()
        
        if mode == OP_MODE_WRITE:
            self.write_widgets_frame.pack(fill=tk.X)
            self.format_combo.config(state="readonly") # 포맷 선택 가능
        else: # READ
            self.read_widgets_frame.pack(fill=tk.X)
            self.format_combo.config(state="disabled") # 읽기는 포맷 무관

    def apply_values(self):
        global current_speed, current_direction
        try:
            s = float(self.speed_var.get())
            d = int(self.direction_var.get())
            with lock:
                current_speed = s
                current_direction = d
            self.update_gui_log(f"[설정] 속도:{s}, 방향:{d}")
        except:
            messagebox.showerror("오류", "숫자만 입력하세요")

    def toggle_pause(self):
        global is_paused
        with lock:
            is_paused = not is_paused
            self.btn_pause.config(text="전송 재개" if is_paused else "일시 정지")

    def update_gui_log(self, msg):
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_text.see(tk.END)

    # [핵심 수정 2] 파싱된 데이터를 화면 상단에 업데이트
    def update_parsed_data(self, msg):
        self.parsed_data_var.set(msg)

    def connect(self):
        global stop_event, is_paused
        stop_event.clear()
        is_paused = False
        
        mode = self.mode_var.get()
        self.comm['mode'] = mode
        
        try:
            if "SERIAL" in mode:
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
        
        self.mode_combo.config(state="readonly")
        
        # LAN 모드인 경우 다시 제한을 걸기 위해 on_mode_change 호출 효과를 줌
        if "LAN" in self.mode_var.get():
            self.op_mode_combo.config(state="readonly", values=OP_MODES_READ_ONLY)
        else:
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