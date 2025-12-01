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

# ---------------------------
# NMEA 문장 생성 함수
# ---------------------------
def calculate_checksum(sentence_body):
    checksum = functools.reduce(operator.xor, (ord(c) for c in sentence_body))
    return f"*{checksum:02X}"

def create_nmea_sentence(direction, speed):
    dir_str = f"{int(direction):03d}"
    speed_str = f"{float(speed):05.1f}"
    body = f"WIMWV,{dir_str},R,{speed_str},M,A"
    return f"${body}{calculate_checksum(body)}\r\n"

# ---------------------------
# NMEA 송신 스레드
# ---------------------------
# **[수정]** App 인스턴스를 받아 GUI 업데이트 요청
def sender_thread(serial_port, interval, app_instance):
    global current_speed, current_direction, is_paused

    while not stop_event.is_set():
        loop_start = time.time()

        with lock:
            if not is_paused:
                msg = create_nmea_sentence(current_direction, current_speed)
                try:
                    serial_port.write(msg.encode('ascii'))
                    
                    # 메인 GUI와 로그 창 업데이트를 위해 App 인스턴스를 통해 요청
                    app_instance.master.after(0, app_instance.update_gui_log, msg)

                except serial.SerialException as e:
                    messagebox.showerror("시리얼 오류", f"시리얼 포트 오류: {e}\n전송을 중단합니다.")
                    stop_event.set()
                except Exception as e:
                    messagebox.showerror("오류", f"알 수 없는 오류 발생: {e}\n전송을 중단합니다.")
                    stop_event.set()
            
        elapsed = time.time() - loop_start
        time.sleep(max(0, interval - elapsed))


# ---------------------------
# GUI 클래스 (메인 창)
# ---------------------------
class AnemometerTesterApp:
    def __init__(self, master):
        self.master = master
        master.title("Anemometer NMEA Tester (GUI)")
        master.protocol("WM_DELETE_WINDOW", self.on_closing) 

        self.ser = None
        self.sender_thread = None
        
        # Tkinter 변수
        self.port_var = tk.StringVar() 
        self.baud_var = tk.IntVar(value=BAUDRATES[1]) 
        self.interval_var = tk.StringVar(value=str(DEFAULT_INTERVAL))
        self.speed_var = tk.StringVar(value="0.0")
        self.direction_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="연결 상태: 대기 중")
        self.latest_data_var = tk.StringVar(value="풍속: 0.0 m/s, 풍향: 0°") # **[추가]** 최신 데이터 표시 변수
        
        self.log_window = None 
        self.log_text = None   

        self.create_widgets()
        self.update_port_list()
        
    def create_widgets(self):
        # --- 1. 설정 프레임 ---
        setup_frame = ttk.LabelFrame(self.master, text="통신 설정", padding="10")
        setup_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # COM 포트 (콤보박스)
        ttk.Label(setup_frame, text="COM 포트 선택:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_combo = ttk.Combobox(setup_frame, textvariable=self.port_var, state="readonly", width=15)
        self.port_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Button(setup_frame, text="새로고침", command=self.update_port_list, width=8).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(setup_frame, text="장치 관리자 열기", command=self.open_device_manager).grid(row=1, column=0, columnspan=3, pady=5)
        
        # 통신 속도 (라디오 버튼)
        baud_frame = ttk.LabelFrame(setup_frame, text="통신 속도", padding="5")
        baud_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="ew")
        
        for i, baud in enumerate(BAUDRATES):
            ttk.Radiobutton(baud_frame, text=str(baud), variable=self.baud_var, value=baud).grid(row=0, column=i, padx=5, pady=2, sticky="w")

        # 전송 간격
        ttk.Label(setup_frame, text="전송 간격 (초):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.interval_entry = ttk.Entry(setup_frame, textvariable=self.interval_var, width=10)
        self.interval_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # 연결/종료 버튼
        self.connect_button = ttk.Button(setup_frame, text="연결 및 전송 시작", command=self.connect_start)
        self.connect_button.grid(row=4, column=0, columnspan=3, pady=10)
        
        self.disconnect_button = ttk.Button(setup_frame, text="전송 종료 및 연결 해제", command=self.disconnect_stop, state=tk.DISABLED)
        self.disconnect_button.grid(row=5, column=0, columnspan=3, pady=5)
        
        # --- 2. 데이터 제어 프레임 ---
        control_frame = ttk.LabelFrame(self.master, text="데이터 제어", padding="10")
        control_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        # 풍속
        ttk.Label(control_frame, text="풍속 (m/s):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.speed_entry = ttk.Entry(control_frame, textvariable=self.speed_var, width=10, state=tk.DISABLED)
        self.speed_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 풍향
        ttk.Label(control_frame, text="풍향 (도):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.direction_entry = ttk.Entry(control_frame, textvariable=self.direction_var, width=10, state=tk.DISABLED)
        self.direction_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # 값 설정 버튼
        self.set_button = ttk.Button(control_frame, text="값 설정", command=self.set_data, state=tk.DISABLED)
        self.set_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # 일시정지 버튼
        self.pause_button = ttk.Button(control_frame, text="일시정지", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=3, column=0, columnspan=2, pady=5)
        
        # 로그 화면 버튼
        ttk.Button(control_frame, text="전송 로그 새 창 열기", command=self.open_log_window).grid(row=4, column=0, columnspan=2, pady=15)
        
        # --- 3. 메인 창 최신 데이터 및 상태 자리 ---
        # **[수정]** 좌측 하단 최신 데이터 표시
        latest_data_frame = ttk.Frame(self.master, padding="5")
        latest_data_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        self.latest_data_label = ttk.Label(latest_data_frame, textvariable=self.latest_data_var, font=('Helvetica', 12, 'bold'), foreground='blue')
        self.latest_data_label.pack(expand=True, fill=tk.BOTH)
        
        # 메인 창 하단의 상태 표시줄
        self.status_label = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_label.grid(row=2, column=0, columnspan=2, sticky="ew")
        

    def open_device_manager(self):
        try:
            if os.name == 'nt': 
                os.startfile('devmgmt.msc')
            elif sys.platform == 'darwin': 
                os.system('open /System/Applications/Utilities/System\ Information.app')
            else: 
                 messagebox.showinfo("정보", "현재 운영체제에서는 장치 관리자를 자동으로 열 수 없습니다.\n수동으로 열어주세요.")
        except Exception as e:
            messagebox.showerror("오류", f"장치 관리자 열기 실패: {e}")
            
    def update_port_list(self):
        ports = list_ports.comports()
        port_names = [port.device for port in ports]
        
        self.port_combo['values'] = port_names
        if port_names:
            self.port_var.set(port_names[0])
        else:
            self.port_var.set("포트 없음")

    def open_log_window(self):
        """전송 로그 (RAW 데이터)를 표시할 별도의 Toplevel 창을 생성합니다."""
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.lift() 
            return

        self.log_window = Toplevel(self.master)
        self.log_window.title("NMEA RAW 데이터 로그")
        self.log_window.geometry("500x300")
        
        self.log_text = tk.Text(self.log_window, height=15, width=60, state=tk.NORMAL, font=('Consolas', 10))
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_scrollbar = ttk.Scrollbar(self.log_window, command=self.log_text.yview)
        self.log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=self.log_scrollbar.set)
        
        self.log_window.protocol("WM_DELETE_WINDOW", lambda: self.log_window.destroy())
        
        self.update_status("로그 창 열림: RAW 데이터가 새 창에 기록됩니다.")

    # **[수정]** 스레드에서 호출되어 GUI를 업데이트하는 함수
    def update_gui_log(self, nmea_msg):
        """
        메인 스레드에서 실행되며, 로그 창과 메인 창의 최신 데이터를 업데이트합니다.
        """
        # 1. 새 로그 창에 RAW 데이터 출력
        if self.log_window and self.log_window.winfo_exists() and self.log_text:
            self.log_text.insert(tk.END, f"전송: {nmea_msg.strip()}\n")
            self.log_text.see(tk.END)
            
        # 2. 메인 창 좌측 하단에 최신 데이터 값 출력 (NMEA 파싱)
        try:
            # NMEA 문장 파싱 (WIMWV,각도,R,속도,M,A*checksum)
            parts = nmea_msg.strip().split('*')[0].split(',')
            if len(parts) >= 5 and parts[0] == '$WIMWV':
                direction = int(parts[1].lstrip('0')) # 359
                speed = float(parts[3]) # 060.0 -> 60.0
                
                new_data_str = f"풍속: {speed:.1f} m/s, 풍향: {direction}°"
                self.latest_data_var.set(new_data_str)
            
        except (IndexError, ValueError):
            # 파싱 오류 발생 시 기본값 유지 또는 오류 메시지 출력
            # self.latest_data_var.set("데이터 파싱 오류") 
            pass


    def update_status(self, message):
        """상태 표시줄에만 메시지를 출력합니다."""
        self.status_var.set(message)
        
    def set_data(self):
        global current_speed, current_direction, lock
        try:
            speed = float(self.speed_var.get())
            direction = int(self.direction_var.get())
            
            if not (0 <= direction <= 359):
                raise ValueError("풍향은 0~359 범위여야 합니다.")
            
            with lock:
                current_speed = speed
                current_direction = direction
            
            self.update_status(f"데이터 설정: 풍속 {speed} m/s, 풍향 {direction}도")
            
        except ValueError as e:
            messagebox.showerror("입력 오류", f"유효하지 않은 값입니다.\n{e}")

    def toggle_pause(self):
        global is_paused, lock
        with lock:
            is_paused = not is_paused
            status = "일시정지됨" if is_paused else "전송 중"
            self.pause_button.config(text=f"{'재개' if is_paused else '일시정지'}")
            self.update_status(f"전송 상태: {status}")

    def connect_start(self):
        """시리얼 포트를 열고 전송 스레드를 시작합니다."""
        global stop_event, is_paused
        
        try:
            port = self.port_var.get().strip()
            baud = self.baud_var.get()
            interval = float(self.interval_var.get())
            
            if port == "포트 없음" or not port:
                 raise ValueError("유효한 COM 포트를 선택하거나 새로고침하세요.")

        except ValueError as e:
            messagebox.showerror("설정 오류", str(e))
            return

        # 포트 열기 및 스레드 시작
        try:
            self.ser = serial.Serial(port, baud, timeout=1)
            stop_event.clear()
            
            # **[수정]** sender_thread에 App 인스턴스 전체를 전달
            self.sender_thread = threading.Thread(
                target=sender_thread, 
                args=(self.ser, interval, self), 
                daemon=True
            )
            self.sender_thread.start()
            
            self.update_status(f"연결 성공: {port} ({baud} bps), {interval}초 간격 전송 시작")
            self.toggle_controls(True) 

        except serial.SerialException as e:
            messagebox.showerror("연결 오류", f"포트 열기 실패: {port} - {e}")
        except Exception as e:
            messagebox.showerror("오류", f"예상치 못한 오류 발생: {e}")

    def disconnect_stop(self):
        if self.ser and self.ser.is_open:
            stop_event.set()
            if self.sender_thread and self.sender_thread.is_alive():
                 self.sender_thread.join(1) 

            self.ser.close()
            self.ser = None
            
            self.toggle_controls(False) 
            self.update_status("연결 상태: 연결 해제됨 (대기 중)")
            
    def toggle_controls(self, connected):
        state = tk.NORMAL if connected else tk.DISABLED
        
        self.port_combo.config(state=tk.DISABLED if connected else "readonly")
        self.interval_entry.config(state=tk.DISABLED if connected else tk.NORMAL)
        
        self.connect_button.config(state=tk.DISABLED if connected else tk.NORMAL)
        self.disconnect_button.config(state=tk.NORMAL if connected else tk.DISABLED)
        
        self.speed_entry.config(state=state)
        self.direction_entry.config(state=state)
        self.set_button.config(state=state)
        self.pause_button.config(state=state)
        self.pause_button.config(text="일시정지") 
        
        for widget in self.master.winfo_children():
            if isinstance(widget, ttk.LabelFrame) and widget.cget("text") == "통신 설정":
                for child in widget.winfo_children():
                    if isinstance(child, ttk.LabelFrame) and child.cget("text") == "통신 속도":
                        for rb in child.winfo_children():
                            if isinstance(rb, ttk.Radiobutton):
                                rb.config(state=tk.DISABLED if connected else tk.NORMAL)


    def on_closing(self):
        if self.log_window and self.log_window.winfo_exists():
            self.log_window.destroy()
        if self.ser and self.ser.is_open:
            self.disconnect_stop()
        self.master.destroy()

# ---------------------------
# 프로그램 실행
# ---------------------------
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AnemometerTesterApp(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("심각한 오류", f"프로그램 실행 중 오류 발생: {e}")