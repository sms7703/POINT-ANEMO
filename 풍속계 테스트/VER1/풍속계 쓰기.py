import serial
import time
import threading
import functools
import operator
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
from serial.tools import list_ports
import sys
import os
import struct

# ---------------------------
# 전역 상태 변수 (스레드 공유)
# ---------------------------
current_speed = 0.0
current_direction = 0
is_paused = False
lock = threading.Lock()
stop_event = threading.Event()

# --- 기본 설정 ---
DEFAULT_INTERVAL = 0.1
BAUDRATES = [2400, 4800, 9600, 19200, 38400]
COMM_FORMATS = ["WMT52", "703", "Blue Sonic"]

# 703 포맷 고정값
HEADER_703 = 0x01
LENGTH_703 = 0x06

# ================================
# NMEA ($WIMWV) 생성 함수
# ================================
def calculate_checksum_nmea(sentence_body):
    checksum = functools.reduce(operator.xor, (ord(c) for c in sentence_body))
    return f"*{checksum:02X}"

def create_nmea_sentence(direction, speed, format_type="WMT52"):
    dir_str = f"{int(direction):03d}"          # 3자리 고정
    speed_str = f"{float(speed):.1f}"          # 3~4자리 (3.0, 12.5)

    if format_type == "Blue Sonic":
        body = f"WIMWV,{speed_str},R,{dir_str},M,A"
    else:
        body = f"WIMWV,{dir_str},R,{speed_str},M,A"

    return f"${body}{calculate_checksum_nmea(body)}\r\n"

# ================================
# 703 포맷 생성 함수
# ================================
def calculate_checksum_703(data_bytes_without_checksum):
    byte_sum = sum(data_bytes_without_checksum)
    return (0x100 - (byte_sum & 0xFF)) & 0xFF

def create_703_sentence(direction, speed):
    speed_scaled = int(speed * 100)
    direction_scaled = int(direction * 20)

    data_core = struct.pack('<BBH', HEADER_703, LENGTH_703, speed_scaled)
    data_core += struct.pack('>H', direction_scaled)

    checksum = calculate_checksum_703(data_core)
    final_bytes = data_core + struct.pack('B', checksum)

    # 로그 출력용 Hex 문자열
    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes

# ================================
# 송신 스레드
# ================================
def sender_thread(serial_port, interval, app_instance, comm_format):
    global current_speed, current_direction, is_paused

    while not stop_event.is_set():
        loop_start = time.time()

        with lock:
            if not is_paused:
                msg_display = ""
                data_to_send = None

                if comm_format == "WMT52":
                    msg_display = create_nmea_sentence(current_direction, current_speed, "WMT52")
                    data_to_send = msg_display.encode('ascii')
                elif comm_format == "Blue Sonic":
                    msg_display = create_nmea_sentence(current_direction, current_speed, "Blue Sonic")
                    data_to_send = msg_display.encode('ascii')
                elif comm_format == "703":
                    msg_display, data_to_send = create_703_sentence(current_direction, current_speed)
                else:
                    msg_display = f"[ERR] Unknown Format: {comm_format}"

                try:
                    if data_to_send:
                        serial_port.write(data_to_send)
                    # GUI 업데이트
                    app_instance.master.after(0, app_instance.update_gui_log, msg_display)
                except Exception as e:
                    messagebox.showerror("전송 오류", str(e))
                    stop_event.set()

        elapsed = time.time() - loop_start
        time.sleep(max(0, interval - elapsed))

# ================================
# GUI 클래스
# ================================
class AnemometerTesterApp:
    def __init__(self, master):
        self.master = master
        master.title("Anemometer NMEA Tester")
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.ser = None
        self.sender_thread = None

        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=BAUDRATES[1])
        self.interval_var = tk.StringVar(value=str(DEFAULT_INTERVAL))
        self.speed_var = tk.StringVar(value="0.0")
        self.direction_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="연결 상태: 대기 중")
        self.latest_data_var = tk.StringVar(value="풍속: 0.0 m/s, 풍향: 0°")
        self.format_var = tk.StringVar(value=COMM_FORMATS[0])

        self.log_window = None
        self.log_text = None

        self.create_widgets()
        self.update_port_list()

    # ---------------------------
    # UI 위젯 구성
    # ---------------------------
    def create_widgets(self):
        setup_frame = ttk.LabelFrame(self.master, text="통신 설정", padding=10)
        setup_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        ttk.Label(setup_frame, text="통신 포맷:").grid(row=0, column=0, sticky="w")
        self.format_combo = ttk.Combobox(setup_frame, textvariable=self.format_var, state="readonly",
                                        values=COMM_FORMATS, width=15)
        self.format_combo.grid(row=0, column=1)

        ttk.Label(setup_frame, text="COM 포트:").grid(row=1, column=0, sticky="w")
        self.port_combo = ttk.Combobox(setup_frame, textvariable=self.port_var, state="readonly", width=15)
        self.port_combo.grid(row=1, column=1)

        ttk.Button(setup_frame, text="새로고침", command=self.update_port_list).grid(row=1, column=2, padx=5)
        ttk.Button(setup_frame, text="장치 관리자", command=self.open_device_manager).grid(row=2, column=0, columnspan=3, pady=5)

        baud_frame = ttk.LabelFrame(setup_frame, text="통신 속도", padding=5)
        baud_frame.grid(row=3, column=0, columnspan=3)
        for i, baud in enumerate(BAUDRATES):
            ttk.Radiobutton(baud_frame, text=str(baud), variable=self.baud_var, value=baud).grid(row=0, column=i)

        ttk.Label(setup_frame, text="전송 간격 (초):").grid(row=4, column=0)
        self.interval_entry = ttk.Entry(setup_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=4, column=1)

        self.connect_button = ttk.Button(setup_frame, text="연결 및 전송 시작", command=self.connect_start)
        self.connect_button.grid(row=5, column=0, columnspan=3, pady=10)
        self.disconnect_button = ttk.Button(setup_frame, text="전송 종료", command=self.disconnect_stop, state=tk.DISABLED)
        self.disconnect_button.grid(row=6, column=0, columnspan=3)

        control_frame = ttk.LabelFrame(self.master, text="데이터 설정", padding=10)
        control_frame.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(control_frame, text="풍속 (m/s):").grid(row=0, column=0)
        self.speed_entry = ttk.Entry(control_frame, textvariable=self.speed_var, width=10, state=tk.DISABLED)
        self.speed_entry.grid(row=0, column=1)

        ttk.Label(control_frame, text="풍향 (도):").grid(row=1, column=0)
        self.direction_entry = ttk.Entry(control_frame, textvariable=self.direction_var, width=10, state=tk.DISABLED)
        self.direction_entry.grid(row=1, column=1)

        self.set_button = ttk.Button(control_frame, text="값 설정", command=self.set_data, state=tk.DISABLED)
        self.set_button.grid(row=2, column=0, columnspan=2, pady=5)

        self.pause_button = ttk.Button(control_frame, text="일시정지", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Button(control_frame, text="전송 로그 확인", command=self.open_log_window).grid(row=4, column=0, columnspan=2, pady=10)

        latest_data_frame = ttk.Frame(self.master)
        latest_data_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        ttk.Label(latest_data_frame, textvariable=self.latest_data_var, font=("Helvetica", 12, "bold"),
                foreground="blue").pack()

        self.status_label = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_label.grid(row=2, column=0, columnspan=2, sticky="ew")

    # ---------------------------
    # 포트 새로고침
    # ---------------------------
    def update_port_list(self):
        ports = list_ports.comports()
        names = [p.device for p in ports]
        self.port_combo["values"] = names
        if names:
            self.port_var.set(names[0])
        else:
            self.port_var.set("포트 없음")

    # ---------------------------
    # 장치 관리자 열기
    # ---------------------------
    def open_device_manager(self):
        try:
            os.startfile("devmgmt.msc")
        except:
            messagebox.showerror("오류", "장치 관리자를 열 수 없습니다.")

    # ---------------------------
    # 로그 창 열기
    # ---------------------------
    def open_log_window(self):
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.lift()
            return

        self.log_window = Toplevel(self.master)
        self.log_window.title("전송 RAW 로그")
        self.log_window.geometry("500x300")

        self.log_text = tk.Text(self.log_window, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    # ---------------------------
    # GUI 로그 업데이트
    # ---------------------------
    def update_gui_log(self, msg):
        if self.log_window and self.log_window.winfo_exists():
            self.log_text.insert(tk.END, f"전송: {msg}\n")
            self.log_text.see(tk.END)

        with lock:
            speed = current_speed
            direction = current_direction

        self.latest_data_var.set(f"풍속: {speed:.1f} m/s, 풍향: {direction}°")

    # ---------------------------
    # 값 설정
    # ---------------------------
    def set_data(self):
        global current_speed, current_direction
        try:
            speed = float(self.speed_var.get())
            direction = int(self.direction_var.get())
            if not 0 <= direction <= 359:
                raise ValueError("풍향은 0~359 범위")

            with lock:
                current_speed = speed
                current_direction = direction

            self.status_var.set(f"데이터 설정됨: {speed} m/s, {direction}°")
        except ValueError as e:
            messagebox.showerror("입력 오류", str(e))

    # ---------------------------
    # 일시정지 토글
    # ---------------------------
    def toggle_pause(self):
        global is_paused
        with lock:
            is_paused = not is_paused
            self.pause_button.config(text="재개" if is_paused else "일시정지")
            self.status_var.set("일시정지됨" if is_paused else "전송 중")

    # ---------------------------
    # 연결 및 전송 시작
    # ---------------------------
    def connect_start(self):
        global stop_event, is_paused

        try:
            port = self.port_var.get()
            baud = self.baud_var.get()
            interval = float(self.interval_var.get())
            if port == "포트 없음":
                raise ValueError()
        except:
            messagebox.showerror("입력 오류", "설정을 확인하세요.")
            return

        try:
            self.ser = serial.Serial(port, baud, timeout=1)
            stop_event.clear()
            is_paused = False

            self.sender_thread = threading.Thread(
                target=sender_thread,
                args=(self.ser, interval, self, self.format_var.get()),
                daemon=True
            )
            self.sender_thread.start()

            self.toggle_controls(True)
            self.status_var.set(f"연결됨: {port}, {baud}bps")

        except serial.SerialException as e:
            messagebox.showerror("연결 실패", str(e))

    # ---------------------------
    # 연결 종료
    # ---------------------------
    def disconnect_stop(self):
        stop_event.set()
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except:
                pass

        self.toggle_controls(False)
        self.status_var.set("연결 해제됨")

    # ---------------------------
    # UI 상태 제어
    # ---------------------------
    def toggle_controls(self, connected):
        state = tk.NORMAL if connected else tk.DISABLED
        self.speed_entry.config(state=state)
        self.direction_entry.config(state=state)
        self.set_button.config(state=state)
        self.pause_button.config(state=state)
        self.connect_button.config(state=tk.DISABLED if connected else tk.NORMAL)
        self.disconnect_button.config(state=tk.NORMAL if connected else tk.DISABLED)
        self.format_combo.config(state="disabled" if connected else "readonly")
        self.port_combo.config(state="disabled" if connected else "readonly")
        self.interval_entry.config(state="disabled" if connected else tk.NORMAL)

    # ---------------------------
    # 창 종료 처리
    # ---------------------------
    def on_closing(self):
        stop_event.set()
        if self.ser and self.ser.is_open:
            self.ser.close()
        self.master.destroy()

# ================================
# 프로그램 시작
# ================================
if __name__ == "__main__":
    root = tk.Tk()
    app = AnemometerTesterApp(root)
    root.mainloop()
