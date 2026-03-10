# 🌐 Universal Signal Webhook

A powerful, Flask-based middleware that acts as a central hub for IT monitoring and ticketing systems, forwarding alerts from **Grafana, Zabbix, Observium, and GLPI** to **Signal Messenger**.

![Signal Notifications](https://img.shields.io/badge/Signal-Blue?style=for-the-badge&logo=signal&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

## 🚀 Features

- **Multi-Source Support**: Centralized handling for Grafana, Zabbix, Observium, and GLPI alerts.
- **Smart Throttling**: Avoid alert fatigue with fingerprint-based suppression for duplicate alerts.
- **Direct GLPI Routing**: Automatically routes tickets to assigned technicians based on technician name mapping.
- **Recovery Auto-Bypass**: Ensures resolution messages always get through, even when throttled.
- **Live Dashboard**: Real-time monitoring of alert volume, throttling stats, and system logs.
- **Dynamic Endpoints**: Create custom webhook endpoints on-the-fly via the management API.
- **Secure Authentication**: Protected dashboard and configuration management.

## 🛠️ Tech Stack

- **Backend**: Python 3.x, Flask
- **Monitoring Integration**: Grafana, Zabbix, Observium
- **Ticketing Integration**: GLPI
- **Messaging**: Signal Messenger (via Signal-CLI-REST-API)

## 📦 Project Structure

```bash
.
├── app.py              # Main application logic & API
├── dashboard.html      # Real-time monitoring dashboard
├── login.html          # Secure login portal
├── technicians.json    # Name-to-Phone mapping for GLPI
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

## ⚙️ Configuration

1. **Technician Mapping**: Add your team's phone numbers in `technicians.json`:
   ```json
   {
     "Abhishek D": "+919876543210",
     "Krishnanunni A": "+919012345678"
   }
   ```
2. **Signal Integration**: Ensure your `signal-cli-rest-api` instance is running and reachable.
3. **Throttling**: Adjust default silence periods (in hours) via the dashboard or `config.json`.

## 🖥️ Running Locally

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the server:
   ```bash
   python app.py
   ```
3. Default access: `http://localhost:5000`

## 🛡️ Security Note

This project is designed for internal network monitoring. Always ensure proper SSL/TLS termination (e.g., via Nginx reverse proxy) before exposing it to external networks.

---

Created with ❤️ by [Sanjan Lal](https://github.com/sanjanlal)
