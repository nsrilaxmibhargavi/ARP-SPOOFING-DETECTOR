# Visual Overview – ARP Spoofing Detection System

This section provides a visual walkthrough of the ARP Spoofing Detection System, highlighting its interface, runtime behavior, and alerting mechanism.

---

## 1️. Application Idle State (Before Monitoring)

<p align="center">
  <img width="1784" height="1285" alt="Screenshot 2026-01-11 225246" src="https://github.com/user-attachments/assets/dbd01c44-bf2a-450c-9cfd-7331ca1cda3c" >
</p>


📝 **What this shows:**
- The application has started successfully
- Monitoring is not active
- No packets or attacks detected yet
- User is ready to start monitoring

🧠 **Purpose:**  
Demonstrates the default state of the system before network analysis begins.

---

## 2️. Monitoring in Progress & Simulated Attack Detection

<p align="center">
  <img width="1793" height="632" alt="Screenshot 2026-01-11 225310" src="https://github.com/user-attachments/assets/10bd83a2-51c7-4e0a-9617-0a9b13992d02" >
</p>


📝 **What this shows:**
- ARP packet sniffing is active
- Baseline ARP table captured
- Gateway added to whitelist
- A simulated ARP spoofing attack detected
- Attack count increased
- Email alert successfully sent

🧠 **Purpose:**  
Shows real-time detection, logging, alerting, and status updates while monitoring is running.

---

## 3️. Email Alert Notification

<p align="center">
  <img width="1461" height="910" alt="Screenshot 2026-01-11 225411" src="https://github.com/user-attachments/assets/3d86a175-1353-4ecd-ab5f-0980dfb0b3b8" >
</p>


📝 **What this shows:**
- Automatic email alert triggered on detection
- Timestamp of attack
- Attacker IP address
- Original and spoofed MAC addresses

🧠 **Purpose:**  
Demonstrates the alerting mechanism and confirms successful email notification delivery.

---

## 🔍 Summary

The visual overview confirms that the system:
- Accurately monitors ARP traffic
- Detects spoofing attempts
- Updates counters and logs in real time
- Sends detailed email alerts
- Provides a clear and user-friendly GUI

This validates both the **functional correctness** and **usability** of the application.
