#!/usr/bin/env python3
from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
from capture import start_capture, metrics  # Import metrics directly

# Configuration
HOST = "0.0.0.0"
PORT = 5000
INTERFACE = "enp0s3"

# Flask app with SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

@app.route('/')
def dashboard():
    """Render the real-time dashboard."""
    return render_template('dashboard.html', metrics=metrics, INTERFACE=INTERFACE)

@app.route('/history')
def history():
    """Render the historical data page with packet counts and alerts."""
    import sqlite3
    conn = sqlite3.connect('traffic.db')
    c = conn.cursor()
    c.execute('SELECT timestamp, total_packets, tcp, udp, icmp, syn_count FROM packet_counts ORDER BY timestamp DESC')
    packet_data = c.fetchall()
    c.execute('SELECT DISTINCT ip FROM source_ips ORDER BY ip')
    src_ips = [row[0] for row in c.fetchall()]
    c.execute('SELECT DISTINCT ip FROM dest_ips ORDER BY ip')
    dst_ips = [row[0] for row in c.fetchall()]
    c.execute('SELECT timestamp, message FROM traffic_alerts ORDER BY timestamp DESC')
    traffic_alerts = c.fetchall()
    c.execute('SELECT timestamp, message FROM threat_alerts ORDER BY timestamp DESC')
    threat_alerts = c.fetchall()
    conn.close()
    return render_template('history.html', packet_data=packet_data, src_ips=src_ips, dst_ips=dst_ips, 
                          traffic_alerts=traffic_alerts, threat_alerts=threat_alerts)

if __name__ == "__main__":
    try:
        capture_thread = threading.Thread(target=lambda: start_capture(socketio), daemon=True)
        capture_thread.start()
        print(f"Starting web server with WebSockets at http://{HOST}:{PORT}")
        print(f"Dashboard: http://{HOST}:{PORT}/")
        print(f"History: http://{HOST}:{PORT}/history")
        socketio.run(app, host=HOST, port=PORT, debug=False)
    except PermissionError:
        print("Error: Run this script with sudo (e.g., 'sudo venv/bin/python3 main.py').")
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Error: {e}")
