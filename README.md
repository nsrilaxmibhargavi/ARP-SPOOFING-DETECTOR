# ARP-SPOOOFING-DETECTOR
<p align="center">
       <img width="1280" height="674" alt="image_2026-01-10_22-25-10" src="https://github.com/user-attachments/assets/95e0ff92-1744-482a-8e30-f7312b105433">
</p>


## Definition
ARP Spoofing Detection System is a network security application that monitors ARP (Address Resolution Protocol) traffic to detect malicious attempts where an attacker tries to associate their MAC address with a legitimate IP address. The system alerts the user when spoofing activity is detected and provides real-time monitoring through a graphical interface.


<p align="center">
       <img src="https://github.com/user-attachments/assets/aa714d18-0fd1-4ca2-84f8-d47d27ae60a4" alt="demo" width=600>
</p>

---

## Project Objective

- To monitor ARP traffic in real time and identify suspicious MAC–IP address mismatches.
- To detect ARP spoofing attacks with minimal false positives using baseline comparison and whitelisting.
- To provide a user-friendly graphical interface for starting, stopping, and monitoring network activity.
- To generate alerts through logs, desktop notifications, sound, and email when an attack is detected.
- To maintain per-IP attack history for analyzing repeated spoofing attempts.
- To allow safe demonstration of ARP spoofing detection using a simulation mode without generating real attacks.
- To enhance awareness of network-level attacks and defensive security mechanisms.

---
### Installation:
To run this project locally, follow these steps:

- Clone the repository: <br>

       git clone https://github.com/nsrilaxmibhargavi/ARP-SPOOFING-DETECTOR

- Navigate to the project directory:
cd ARP-SPOOFING-DETECTOR
- Ensure you have Python installed on your system.
- Install the required dependencies.
- Run the application:
    `python main.py`

---
<p align="center">
       <img width="1024" height="564" alt="image_2026-01-10_22-25-00" src="https://github.com/user-attachments/assets/5dc652d8-e85c-4949-8b45-4e5991471f48">
</p>

---

## Libraries Used 

- **scapy** – Used to sniff and analyze ARP packets from the network.
- **customtkinter** – Used to create a modern and responsive graphical user interface.
- **smtplib** – Used to send email alerts using SMTP.
- **email.mime** – Used to format email messages properly.
- **plyer** – Used to display desktop notifications.
- **winsound** – Used to generate alert sounds on detection.
- **threading** – Used to run packet sniffing without freezing the GUI.
- **subprocess** – Used to fetch system ARP table and gateway details.
- **datetime** – Used to add timestamps to logs and alerts.

---

## Steps to Perform

1. Install all required libraries using `pip`.
2. Configure sender email, app password, and receiver email in the code.
3. Run the application using `python main.py`.
4. Click **Start Monitoring** to begin ARP packet inspection.
5. The system captures a baseline ARP table and whitelists the gateway.
6. If ARP spoofing is detected, alerts are generated (log, sound, notification, email).
7. Use **Simulate Attack** to demonstrate detection without real network attacks.
8. Click **Stop Monitoring** to safely stop packet capture.

---

## Result

- The system successfully monitors ARP traffic in real time.
- It detects ARP spoofing attempts by identifying MAC–IP mismatches.
- Alerts are generated through logs, notifications, sound, and email.
- Attack history is maintained per IP address.
- Whitelisting reduces false positives.
- Simulation mode allows safe demonstration of attacks.

---
<p align="center">
       <img src="https://github.com/user-attachments/assets/a9aa0ad4-ffba-4fb0-9405-386f017e020a" alt="demo" width=600>
</p>
---

## Conclusion

This project demonstrates an effective approach to detecting ARP spoofing attacks using Python. By combining packet analysis with a user-friendly GUI and alert mechanisms, the system helps in identifying network threats in real time. The project highlights key cybersecurity concepts such as spoofing detection, incident monitoring, and alert generation, making it suitable for academic and practical security learning.

---
