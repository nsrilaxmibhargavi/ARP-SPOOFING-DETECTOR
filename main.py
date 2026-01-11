import subprocess
import threading
import smtplib
from datetime import datetime
from scapy.all import sniff, ARP
from plyer import notification
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import customtkinter as ctk
import winsound

# ================= EMAIL CONFIG =================
# MUST be a real Gmail + 16-char App Password
SENDER_EMAIL = "" # Your Gmail here
APP_PASSWORD = "" # Your App Password here
RECEIVER_EMAIL = "" # Recipient email here
# =================================================

# ---------------- FONT CONFIG ----------------
APP_FONT = "Segoe UI"
STATUS_FONT = ("Segoe UI", 16, "bold")
BUTTON_FONT = ("Segoe UI", 12)
LOG_FONT = ("Consolas", 11)

# ---------------- STATE ----------------
baseline_arp = {}
trusted_ips = set()
attack_history = {}

monitoring = False
attack_detected = False
blink_state = True
email_enabled = True

packet_count = 0
attack_count = 0

# ---------------- CUSTOMTKINTER SETUP ----------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("ARP Spoofing Detection System")
app.geometry("900x620")
app.resizable(False, False)

# ---------------- STATUS HEADER ----------------
header = ctk.CTkFrame(app, corner_radius=12, height=55)
header.pack(fill="x", padx=20, pady=(15, 6))

status_frame = ctk.CTkFrame(header, fg_color="transparent")
status_frame.pack(pady=12)

status_dot = ctk.CTkLabel(
    status_frame, text="●", font=("Segoe UI", 16), text_color="#ff3b3b"
)
status_dot.pack(side="left", padx=(0, 6))

status_label = ctk.CTkLabel(
    status_frame,
    text="STATUS: STOPPED",
    font=STATUS_FONT,
    text_color="#ff3b3b"
)
status_label.pack(side="left")

# ---------------- COUNTERS ----------------
counter_frame = ctk.CTkFrame(app, corner_radius=12)
counter_frame.pack(fill="x", padx=20, pady=(0, 6))

packet_label = ctk.CTkLabel(counter_frame, text="Packets: 0", font=(APP_FONT, 12))
packet_label.pack(side="left", padx=15, pady=8)

attack_label = ctk.CTkLabel(
    counter_frame,
    text="Attacks: 0",
    font=(APP_FONT, 12, "bold"),
    text_color="#ff5252"
)
attack_label.pack(side="left", padx=15)

# ---------------- LOG BOX ----------------
log_frame = ctk.CTkFrame(app, corner_radius=12)
log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 8))

log_box = ctk.CTkTextbox(
    log_frame,
    font=LOG_FONT,
    corner_radius=10,
    state="disabled"
)
log_box.pack(fill="both", expand=True, padx=15, pady=15)

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "[INFO]", "WARN": "[WARN]", "ALERT": "[ALERT]"}[level]

    log_box.configure(state="normal")
    log_box.insert("end", f"[{timestamp}] {prefix} {msg}\n")
    log_box.configure(state="disabled")
    log_box.see("end")

# ---------------- WHITELIST (Gateway) ----------------
def add_gateway_to_whitelist():
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode()
        for line in output.splitlines():
            if "Default Gateway" in line and ":" in line:
                gw = line.split(":")[-1].strip()
                trusted_ips.add(gw)
                log(f"Gateway {gw} whitelisted", "INFO")
    except:
        log("Failed to detect gateway", "WARN")

# ---------------- BASELINE ----------------
def get_baseline_arp():
    baseline_arp.clear()
    output = subprocess.check_output("arp -a", shell=True).decode()
    for line in output.splitlines():
        if "-" in line and "." in line:
            parts = line.split()
            if len(parts) >= 2:
                baseline_arp[parts[0]] = parts[1].replace("-", ":").lower()
    log("Baseline ARP table captured", "INFO")

# ---------------- EMAIL ----------------
def send_email_alert(ip, original_mac, spoofed_mac):
    if not email_enabled:
        return

    subject = "⚠ ARP Spoofing Detected"
    body = f"""
ARP Spoofing Detected!

Time: {datetime.now()}
IP Address: {ip}
Original MAC: {original_mac}
Spoofed MAC: {spoofed_mac}
"""

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()

        log("Email alert sent", "INFO")
    except Exception as e:
        log(f"Email error: {e}", "WARN")

# ---------------- PACKET ANALYSIS ----------------
def detect_arp_spoof(packet):
    global packet_count, attack_detected, attack_count

    if not monitoring:
        return

    if packet.haslayer(ARP):
        packet_count += 1
        packet_label.configure(text=f"Packets: {packet_count}")

    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc.lower()

        if ip in trusted_ips:
            return

        if ip in baseline_arp and mac != baseline_arp[ip]:
            attack_history[ip] = attack_history.get(ip, 0) + 1

            if not attack_detected:
                attack_detected = True
                attack_count += 1
                attack_label.configure(text=f"Attacks: {attack_count}")

                log("ARP SPOOFING DETECTED", "ALERT")
                log(f"IP Address: {ip}", "ALERT")
                log(f"Attempts from {ip}: {attack_history[ip]}", "ALERT")

                winsound.Beep(1000, 300)
                notification.notify(
                    title="ARP Spoofing Detected",
                    message=f"{ip} MAC mismatch!",
                    timeout=6
                )

                send_email_alert(ip, baseline_arp[ip], mac)

def sniff_packets():
    sniff(filter="arp", prn=detect_arp_spoof, store=False)

# ---------------- CONTROLS ----------------
def start_monitoring():
    global monitoring, attack_detected
    monitoring = True
    attack_detected = False

    get_baseline_arp()
    add_gateway_to_whitelist()

    status_label.configure(text="STATUS: RUNNING", text_color="#00e676")
    threading.Thread(target=sniff_packets, daemon=True).start()
    log("Monitoring started", "INFO")

def stop_monitoring():
    global monitoring
    monitoring = False
    status_label.configure(text="STATUS: STOPPED", text_color="#ff3b3b")
    log("Monitoring stopped", "WARN")

# ---------------- SIMULATION (EMAIL FIXED) ----------------
def simulate_intrusion():
    fake_ip = "192.168.1.1"
    real_mac = "aa:bb:cc:dd:ee:ff"
    fake_mac = "11:22:33:44:55:66"

    attack_history[fake_ip] = attack_history.get(fake_ip, 0) + 1

    log("SIMULATED ARP SPOOFING DETECTED", "ALERT")
    log(f"IP Address: {fake_ip}", "ALERT")
    log(f"Attempts from {fake_ip}: {attack_history[fake_ip]}", "ALERT")

    winsound.Beep(1000, 300)
    notification.notify(
        title="ARP Spoofing Detected (Simulation)",
        message=f"{fake_ip} MAC mismatch!",
        timeout=6
    )

    send_email_alert(fake_ip, real_mac, fake_mac)

def clear_log():
    log_box.configure(state="normal")
    log_box.delete("1.0", "end")
    log_box.configure(state="disabled")

# ---------------- BUTTON BAR ----------------
btn_frame = ctk.CTkFrame(app, corner_radius=12)
btn_frame.pack(fill="x", padx=20, pady=(0, 10))

ctk.CTkButton(btn_frame, text="▶ Start",
              fg_color="#2ecc71", hover_color="#27ae60",
              font=BUTTON_FONT, command=start_monitoring).pack(side="left", padx=8)

ctk.CTkButton(btn_frame, text="■ Stop",
              fg_color="#e74c3c", hover_color="#c0392b",
              font=BUTTON_FONT, command=stop_monitoring).pack(side="left", padx=8)

ctk.CTkButton(btn_frame, text="⚠ Simulate",
              fg_color="#42a5f5", hover_color="#1e88e5",
              font=BUTTON_FONT, command=simulate_intrusion).pack(side="left", padx=8)

ctk.CTkButton(btn_frame, text="🧹 Clear Log",
              fg_color="#455a64", hover_color="#37474f",
              font=BUTTON_FONT, command=clear_log).pack(side="left", padx=8)

# ---------------- SAFE SHUTDOWN ----------------
def on_close():
    global monitoring
    monitoring = False
    log("Application closed safely", "INFO")
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_close)

# ---------------- RUN ----------------
app.mainloop()
