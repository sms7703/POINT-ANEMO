import serial
import socket
import time
import threading
import functools
import operator
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
from serial.tools import list_ports
import struct
import os

# ---------------------------
# 글로벌 상태 변수
# ---------------------------
current_speed = 0.0
current_direction = 0
is_paused = False
lock = threading.Lock()
stop_event = threading.Event()

DEFAULT_INTERVAL = 0.1
BAUDRATES = [2400, 4800, 9600, 19200, 38400]
COMM_FORMATS = ["WMT52", "703", "Blue Sonic"]

# 703 format fixed values
HEADER_703 = 0x01
LENGTH_703 = 0x06


# ===================================================
# NMEA Sentence
# ===================================================
def calculate_checksum_nmea(sentence_body):
    checksum = functools.reduce(operator.xor, (ord(c) for c in sentence_body))
    return f"*{checksum:02X}"


def create_nmea_sentence(direction, speed, format_type="WMT52"):
    dir_str = f"{int(direction):03d}"
    speed_str = f"{float(speed):.1f}"

    if format_type == "Blue Sonic":
        body = f"WIMWV,{speed_str},R,{dir_str},M,A"
    else:
        body = f"WIMWV,{dir_str},R,{speed_str},M,A"

    return f"${body}{calculate_checksum_nmea(body)}\r\n"


# ===================================================
# 703 Format
# ===================================================
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

    hex_output = " ".join([f"{b:02X}" for b in final_bytes])
    return hex_output, final_bytes


# ===================================================
# Sender Thread (Serial or TCP Socket)
# ===================================================
def sender_thread(conn, interval, app_instance, comm_format, is_socket=False):
    global current_speed, current_direction, is_paused

    while not stop_event.is_set():
        loop_start = time.time()

        with lock:
            if not is_paused:
                msg_display = ""
                data_to_send = None

                if comm_format == "WMT52":
                    msg_display = create_nmea_sentence(current_direction, current_speed, "WMT52")
                    data_to_send = msg_display.encode("ascii")

                elif comm_format == "Blue Sonic":
                    msg_display = create_nmea_sentence(current_direction, current_speed, "Blue Sonic")
                    data_to_send = msg_display.encode("ascii")

                elif comm_format == "703":
                    msg_display, data_to_send = create_703_sentence(current_direction, current_speed)

                # 실제 전송 처리
                try:
                    if data_to_send:
                        if is_socket:
                            conn.sendall(data_to_send)
                        else:
                            conn.write(data_to_send)

                    # GUI Log
                    app_instance.master.after(0, app_instance.update_gui_log, msg_display)

                except Exception as e:
                    messagebox.showerror("전송 오류", str(e))
                    stop_event.set()

        elapsed = time.time() - loop_start
        time.sleep(max(0, interval - elapsed))


# ===================================================
# GUI Application
# ===================================================
class AnemometerTesterApp:
    def __init__(self, master):
        self.master = master
        master.title("Anemometer Tester (LAN)")

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.ser = None
        self.sock = None
        self.sender_thread = None
        self.is_socket_mode = False

        # UI Variables
        self.comm_mode_var = tk.StringVar(value="SERIAL")
        self.ip_var = tk.StringVar(value="127.0.0.1")
        self.port_tcp_var = tk.StringVar(value="5000")

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

    # ===================================================
    # UI 구성
    # ===================================================
    def create_widgets(self):

        # ------------------ 통신 방식 selection --------------------
        mode_frame = ttk.LabelFrame(self.master, text="통신 방식")
        mode_frame.grid(row=0, column=0, padx=10, pady=5, columnspan=2, sticky="ew")

        ttk.Radiobutton(mode_frame, text="LAN (TCP)", variable=self.comm_mode_var,
                        value="LAN", command=self.update_comm_mode).grid(row=0, column=0, padx=10)

        ttk.Radiobutton(mode_frame, text="SERIAL (COM)", variable=self.comm_mode_var,
                        value="SERIAL", command=self.update_comm_mode).grid(row=0, column=1, padx=10)

        # ------------------ Serial Setting --------------------
        setup_frame = ttk.LabelFrame(self.master, text="공통 설정")
        setup_frame.grid(row=1, column=0, padx=10, pady=10, sticky="n")

        ttk.Label(setup_frame, text="통신 포맷:").grid(row=0, column=0, sticky="w")
        self.format_combo = ttk.Combobox(setup_frame, textvariable=self.format_var, state="readonly",
                                         values=COMM_FORMATS, width=15)
        self.format_combo.grid(row=0, column=1)

        ttk.Label(setup_frame, text="전송 간격 (초):").grid(row=1, column=0, sticky="w")
        self.interval_entry = ttk.Entry(setup_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=1, column=1)

        # ------------------ Serial Setting --------------------
        serial_frame = ttk.LabelFrame(self.master, text="SERIAL 설정")
        serial_frame.grid(row=2, column=0, padx=10, pady=10, sticky="n")

        ttk.Label(serial_frame, text="COM 포트:").grid(row=0, column=0)
        self.port_combo = ttk.Combobox(serial_frame, textvariable=self.port_var, state="readonly", width=15)
        self.port_combo.grid(row=0, column=1)
        ttk.Button(serial_frame, text="새로고침", command=self.update_port_list).grid(row=0, column=2)

        baud_frame = ttk.LabelFrame(serial_frame, text="통신 속도")
        baud_frame.grid(row=1, column=0, columnspan=3)
        for i, baud in enumerate(BAUDRATES):
            ttk.Radiobutton(baud_frame, text=str(baud), variable=self.baud_var, value=baud).grid(row=0, column=i)

        # ------------------ LAN Setting --------------------
        lan_frame = ttk.LabelFrame(self.master, text="LAN 설정")
        lan_frame.grid(row=2, column=1, padx=10, pady=10, sticky="n")

        ttk.Label(lan_frame, text="장비 IP:").grid(row=0, column=0, sticky="w")
        ttk.Entry(lan_frame, textvariable=self.ip_var, width=15).grid(row=0, column=1)

        ttk.Label(lan_frame, text="장비 Port:").grid(row=1, column=0, sticky="w")
        ttk.Entry(lan_frame, textvariable=self.port_tcp_var, width=15).grid(row=1, column=1)

        # ------------------ Connect Buttons --------------------
        self.connect_button = ttk.Button(self.master, text="연결 및 전송 시작",
                                         command=self.connect_start)
        self.connect_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.disconnect_button = ttk.Button(self.master, text="전송 종료",
                                            command=self.disconnect_stop, state=tk.DISABLED)
        self.disconnect_button.grid(row=4, column=0, columnspan=2)

        # ------------------ Data Input --------------------
        data_frame = ttk.LabelFrame(self.master, text="데이터 설정")
        data_frame.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(data_frame, text="풍속 (m/s):").grid(row=0, column=0)
        self.speed_entry = ttk.Entry(data_frame, textvariable=self.speed_var, width=10, state=tk.DISABLED)
        self.speed_entry.grid(row=0, column=1)

        ttk.Label(data_frame, text="풍향 (도):").grid(row=1, column=0)
        self.direction_entry = ttk.Entry(data_frame, textvariable=self.direction_var, width=10, state=tk.DISABLED)
        self.direction_entry.grid(row=1, column=1)

        self.set_button = ttk.Button(data_frame, text="값 설정", command=self.set_data, state=tk.DISABLED)
        self.set_button.grid(row=2, column=0, columnspan=2, pady=5)

        self.pause_button = ttk.Button(data_frame, text="일시정지", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Button(data_frame, text="전송/수신 로그 확인",
                   command=self.open_log_window).grid(row=4, column=0, columnspan=2)

        # ------------------ Latest Status --------------------
        ttk.Label(self.master, textvariable=self.latest_data_var,
                  font=("Helvetica", 12, "bold"), foreground="blue").grid(row=5, column=0, columnspan=2)

        ttk.Label(self.master, textvariable=self.status_var,
                  relief=tk.SUNKEN, anchor="w").grid(row=6, column=0, columnspan=2, sticky="ew")

        self.update_comm_mode()

    # ===================================================
    # 통신 방식 선택 UI 업데이트
    # ===================================================
    def update_comm_mode(self):
        mode = self.comm_mode_var.get()

        if mode == "LAN":
            self.is_socket_mode = True
            self.port_combo.config(state=tk.DISABLED)
            self.speed_entry.config(state=tk.DISABLED)

        else:
            self.is_socket_mode = False
            self.port_combo.config(state="readonly")

    # ===================================================
    # Serial Port Refresh
    # ===================================================
    def update_port_list(self):
        ports = list_ports.comports()
        names = [p.device for p in ports]
        self.port_combo["values"] = names
        if names:
            self.port_var.set(names[0])
        else:
            self.port_var.set("포트 없음")

    # ===================================================
    # 데이터 설정
    # ===================================================
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

    # ===================================================
    # 일시정지
    # ===================================================
    def toggle_pause(self):
        global is_paused
        with lock:
            is_paused = not is_paused
        self.pause_button.config(text="재개" if is_paused else "일시정지")
        self.status_var.set("일시정지됨" if is_paused else "전송 중")

    # ===================================================
    # 연결 + 전송 시작
    # ===================================================
    def connect_start(self):
        global stop_event, is_paused

        try:
            interval = float(self.interval_var.get())
        except:
            messagebox.showerror("입력 오류", "전송 간격이 올바르지 않습니다.")
            return

        stop_event.clear()
        is_paused = False

        if self.comm_mode_var.get() == "SERIAL":
            port = self.port_var.get()
            baud = self.baud_var.get()

            try:
                self.ser = serial.Serial(port, baud, timeout=1)
            except Exception as e:
                messagebox.showerror("연결 실패", str(e))
                return

            self.sender_thread = threading.Thread(
                target=sender_thread,
                args=(self.ser, interval, self, self.format_var.get(), False),
                daemon=True
            )

            self.sender_thread.start()
            self.status_var.set(f"Serial 연결됨: {port}, {baud}bps")

        else:
            # LAN TCP
            ip = self.ip_var.get()
            port_tcp = int(self.port_tcp_var.get())

            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((ip, port_tcp))
            except Exception as e:
                messagebox.showerror("LAN 연결 실패", str(e))
                return

            self.sender_thread = threading.Thread(
                target=sender_thread,
                args=(self.sock, interval, self, self.format_var.get(), True),
                daemon=True
            )

            self.sender_thread.start()
            self.status_var.set(f"LAN 연결됨: {ip}:{port_tcp}")

        self.toggle_controls(True)

    # ===================================================
    # 연결 종료
    # ===================================================
    def disconnect_stop(self):
        stop_event.set()

        try:
            if self.ser:
                self.ser.close()
            if self.sock:
                self.sock.close()
        except:
            pass

        self.toggle_controls(False)
        self.status_var.set("연결 종료됨")

    # ===================================================
    # UI 버튼 상태 전환
    # ===================================================
    def toggle_controls(self, connected):
        state = tk.NORMAL if connected else tk.DISABLED

        self.speed_entry.config(state=state)
        self.direction_entry.config(state=state)
        self.set_button.config(state=state)
        self.pause_button.config(state=state)

        self.connect_button.config(state=tk.DISABLED if connected else tk.NORMAL)
        self.disconnect_button.config(state=tk.NORMAL if connected else tk.DISABLED)

    # ===================================================
    # Log Window
    # ===================================================
    def open_log_window(self):
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.lift()
            return

        self.log_window = Toplevel(self.master)
        self.log_window.title("전송 RAW 로그")
        self.log_window.geometry("500x300")

        self.log_text = tk.Text(self.log_window, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def update_gui_log(self, msg):
        if self.log_window and self.log_window.winfo_exists():
            self.log_text.insert(tk.END, f"전송: {msg}\n")
            self.log_text.see(tk.END)

        self.latest_data_var.set(f"풍속: {current_speed:.1f} m/s, 풍향: {current_direction}°")

    # ===================================================
    # 종료
    # ===================================================
    def on_closing(self):
        stop_event.set()
        try:
            if self.ser:
                self.ser.close()
            if self.sock:
                self.sock.close()
        except:
            pass
        self.master.destroy()


# ===================================================
# Program Start
# ===================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = AnemometerTesterApp(root)
    root.mainloop()
