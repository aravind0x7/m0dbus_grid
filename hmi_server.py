#!/usr/bin/env python3
"""
HMI Web Server - Water Treatment Plant SCADA Interface
Connects to the Modbus PLC simulator and exposes a REST API for the HMI.

VULNERABILITIES (intentional - training lab):
  [V-HMI-001] No authentication on HMI web interface
  [V-HMI-002] API endpoints allow unauthenticated write operations
  [V-HMI-003] Debug mode enabled - stack traces exposed
  [V-HMI-004] CORS wildcard - any origin can interact
  [V-HMI-005] Write log accessible without auth at /api/audit
  [V-HMI-006] Plaintext credentials readable via /api/status
"""

import socket
import struct
import threading
import time
import json
import os
import sys
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, Response

# ── Modbus Client ─────────────────────────────────────────────────────────────

class ModbusClient:
    def __init__(self, host='127.0.0.1', port=502):
        self.host = host
        self.port = port
        self.tid = 0
        self.lock = threading.Lock()

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((self.host, self.port))
        return s

    def _next_tid(self):
        self.tid = (self.tid + 1) % 65536
        return self.tid

    def _request(self, pdu, unit_id=1):
        tid = self._next_tid()
        mbap = struct.pack('>HHHB', tid, 0, len(pdu) + 1, unit_id)
        with self.lock:
            try:
                s = self._connect()
                s.sendall(mbap + pdu)
                resp = s.recv(256)
                s.close()
                return resp
            except Exception as e:
                return None

    def read_coils(self, start, count, unit_id=1):
        pdu = struct.pack('>BHH', 0x01, start, count)
        resp = self._request(pdu, unit_id)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80: return None
        byte_count = resp[8]
        coil_bytes = resp[9:9 + byte_count]
        result = []
        for i in range(count):
            result.append(bool((coil_bytes[i // 8] >> (i % 8)) & 1))
        return result

    def read_holding_registers(self, start, count, unit_id=1):
        pdu = struct.pack('>BHH', 0x03, start, count)
        resp = self._request(pdu, unit_id)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80: return None
        byte_count = resp[8]
        regs = []
        for i in range(byte_count // 2):
            val = struct.unpack('>H', resp[9 + i*2 : 11 + i*2])[0]
            regs.append(val)
        return regs

    def read_input_registers(self, start, count, unit_id=1):
        pdu = struct.pack('>BHH', 0x04, start, count)
        resp = self._request(pdu, unit_id)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80: return None
        byte_count = resp[8]
        regs = []
        for i in range(byte_count // 2):
            val = struct.unpack('>H', resp[9 + i*2 : 11 + i*2])[0]
            regs.append(val)
        return regs

    def write_coil(self, addr, value, unit_id=1):
        val = 0xFF00 if value else 0x0000
        pdu = struct.pack('>BHH', 0x05, addr, val)
        resp = self._request(pdu, unit_id)
        return resp is not None and len(resp) > 7 and not (resp[7] & 0x80)

    def write_register(self, addr, value, unit_id=1):
        pdu = struct.pack('>BHH', 0x06, addr, value)
        resp = self._request(pdu, unit_id)
        return resp is not None and len(resp) > 7 and not (resp[7] & 0x80)

    def write_multiple_registers(self, start, values, unit_id=1):
        count = len(values)
        byte_count = count * 2
        pdu = struct.pack('>BHHB', 0x10, start, count, byte_count)
        for v in values:
            pdu += struct.pack('>H', v)
        resp = self._request(pdu, unit_id)
        return resp is not None and len(resp) > 7 and not (resp[7] & 0x80)

    def get_device_id(self, unit_id=1):
        pdu = bytes([0x11])
        resp = self._request(pdu, unit_id)
        if resp and len(resp) > 9:
            return resp[9:].decode('latin-1', errors='replace')
        return None


# ── Auto-detect PLC port ──────────────────────────────────────────────────────

PLC_HOST = os.environ.get('PLC_HOST', '127.0.0.1')
PLC_PORT = int(os.environ.get('PLC_PORT', '502'))

def get_working_client():
    for port in [PLC_PORT, 5020, 502, 5021, 5022]:
        c = ModbusClient(PLC_HOST, port)
        result = c.read_coils(0, 1)
        if result is not None:
            print(f"[HMI] Connected to PLC at {PLC_HOST}:{port}")
            return c, port
    print(f"[HMI] WARNING: PLC not reachable, using {PLC_HOST}:5020")
    return ModbusClient(PLC_HOST, 5020), 5020


# ── Flask App — serve index.html from same directory as this script ───────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR)
client = ModbusClient(PLC_HOST, PLC_PORT)
audit_log = []

def log_action(action, addr, value, source_ip):
    entry = {"time": datetime.now().isoformat(), "action": action,
             "addr": addr, "value": value, "ip": source_ip}
    audit_log.append(entry)
    if len(audit_log) > 1000:
        audit_log.pop(0)


# CORS wildcard — VULNERABLE [V-HMI-004]
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    # Serve index.html from same directory as this script
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/api/status')
def api_status():
    """Full PLC status — no auth [VULN V-HMI-001]"""
    coils   = client.read_coils(0, 10) or [False]*10
    holding = client.read_holding_registers(0, 12) or [0]*12
    inputs  = client.read_input_registers(0, 11) or [0]*11

    coil_names    = ['pump1','pump2','valve_inlet','valve_outlet',
                     'chlorine_dosing','uv_sterilizer','alarm','emergency_stop',
                     'pump3','heater']
    holding_names = ['pump1_setpoint','tank_hi','tank_lo','pressure_max',
                     'chlorine_sp','ph_hi','ph_lo','temp_sp',
                     'dosing_rate','maintenance_code','system_mode','unit_id']

    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "coils":     dict(zip(coil_names, coils)),
        "sensors": {
            "flow_rate":       inputs[0],
            "tank_level":      inputs[1],
            "inlet_pressure":  inputs[2],
            "outlet_pressure": inputs[3],
            "water_temp":      inputs[4] / 10.0,
            "turbidity":       inputs[5] / 100.0,
            "ph":              inputs[6] / 100.0,
            "chlorine_ppm":    inputs[7] / 100.0,
            "pump1_current":   inputs[8],
            "pump2_current":   inputs[9],
            "runtime_hours":   inputs[10],
        },
        "setpoints": dict(zip(holding_names, holding)),
        "alarms": {
            "active":         coils[6] if len(coils) > 6 else False,
            "emergency_stop": coils[7] if len(coils) > 7 else False,
        }
    })

@app.route('/api/coil/<int:addr>', methods=['POST', 'OPTIONS'])
def write_coil(addr):
    """Write coil — NO AUTH [VULN V-HMI-002]"""
    if request.method == 'OPTIONS':
        return '', 204
    data  = request.get_json() or {}
    value = bool(data.get('value', False))
    ok    = client.write_coil(addr, value)
    log_action('write_coil', addr, value, request.remote_addr)
    return jsonify({"success": ok, "addr": addr, "value": value})

@app.route('/api/register/<int:addr>', methods=['POST', 'OPTIONS'])
def write_register(addr):
    """Write holding register — NO AUTH [VULN V-HMI-002]"""
    if request.method == 'OPTIONS':
        return '', 204
    data  = request.get_json() or {}
    value = int(data.get('value', 0)) & 0xFFFF
    ok    = client.write_register(addr, value)
    log_action('write_register', addr, value, request.remote_addr)
    return jsonify({"success": ok, "addr": addr, "value": value})

@app.route('/api/bulk_write', methods=['POST', 'OPTIONS'])
def bulk_write():
    """Write multiple registers — NO AUTH [VULN]"""
    if request.method == 'OPTIONS':
        return '', 204
    data   = request.get_json() or {}
    start  = int(data.get('start', 0))
    values = [int(v) & 0xFFFF for v in data.get('values', [])]
    ok     = client.write_multiple_registers(start, values)
    log_action('bulk_write', start, values, request.remote_addr)
    return jsonify({"success": ok, "start": start, "count": len(values)})

@app.route('/api/device_info')
def device_info():
    """FC17 device info — info leak [VULN]"""
    info = client.get_device_id()
    return jsonify({"device_id": info, "host": PLC_HOST, "port": client.port})

@app.route('/api/audit')
def audit():
    """Audit log — NO AUTH [VULN V-HMI-005]"""
    return jsonify({"log": audit_log[-100:]})

@app.route('/api/raw_read')
def raw_read():
    """Arbitrary Modbus read — NO AUTH [VULN]"""
    fc    = int(request.args.get('fc', 3))
    start = int(request.args.get('start', 0))
    count = min(int(request.args.get('count', 10)), 125)
    unit  = int(request.args.get('unit', 1))

    if fc == 1:
        data = client.read_coils(start, count, unit)
    elif fc == 3:
        data = client.read_holding_registers(start, count, unit)
    elif fc == 4:
        data = client.read_input_registers(start, count, unit)
    else:
        return jsonify({"error": "fc not supported"}), 400

    return jsonify({"fc": fc, "start": start, "count": count, "unit": unit, "data": data})

@app.route('/api/health')
def health():
    return jsonify({"status": "ok", "plc": f"{PLC_HOST}:{client.port}", "debug": True})


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [HMI] %(levelname)s %(message)s',
                        datefmt='%H:%M:%S')

    client, working_port = get_working_client()

    print(f"[HMI] Serving index.html from: {BASE_DIR}")
    print(f"[HMI] Open browser: http://localhost:8080")
    print(f"[HMI] VULN: No authentication on any endpoint")

    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
