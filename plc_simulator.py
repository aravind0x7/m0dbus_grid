#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         VULNERABLE MODBUS TCP PLC SIMULATOR v1.0                ║
║         OT Security Training Lab - FOR EDUCATIONAL USE          ║
╚══════════════════════════════════════════════════════════════════╝

Simulates a SCADA/ICS environment controlling a water treatment plant.
Intentionally vulnerable for pentesting practice.

VULNERABILITIES PRESENT:
  [V-001] No authentication on Modbus TCP (RFC default - unauthenticated)
  [V-002] No input validation on coil/register writes
  [V-003] Function codes 0x01-0x06, 0x0F, 0x10, 0x11 all enabled (no whitelist)
  [V-004] Device identification (FC 43/0x2B) reveals firmware/vendor info
  [V-005] No rate limiting - susceptible to flooding/replay attacks
  [V-006] Write Multiple Registers allows bulk process value override
  [V-007] Exception responses reveal internal state details
  [V-008] No logging of write operations (writes go undetected)
"""

import socket
import struct
import threading
import time
import random
import json
import logging
import os
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [PLC] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("PLC")

# ── Process simulation state ──────────────────────────────────────────────────

class PLCDataStore:
    """
    Modbus memory map for a Water Treatment Plant PLC:

    COILS (Read/Write bits) - 0x (addresses 0-99):
      0x00  PUMP_1_RUN         - Main water pump running
      0x01  PUMP_2_RUN         - Backup pump running
      0x02  VALVE_INLET_OPEN   - Inlet valve open
      0x03  VALVE_OUTLET_OPEN  - Outlet valve open
      0x04  CHLORINE_DOSING    - Chlorine dosing pump ON
      0x05  UV_STERILIZER      - UV sterilizer active
      0x06  ALARM_ACTIVE       - System alarm flag
      0x07  EMERGENCY_STOP     - Emergency stop engaged
      0x08  PUMP_3_RUN         - Chemical pump
      0x09  HEATER_ON          - Water heater

    DISCRETE INPUTS (Read-only bits) - 1x (addresses 0-9):
      1x00  FLOW_SENSOR_OK     - Flow sensor healthy
      1x01  LEVEL_SENSOR_OK    - Level sensor healthy
      1x02  PRESSURE_NORMAL    - Pressure within range
      1x03  QUALITY_SENSOR_OK  - Water quality sensor OK
      1x04  DOOR_CLOSED        - Control cabinet door

    INPUT REGISTERS (Read-only 16-bit) - 3x (addresses 0-19):
      3x00  FLOW_RATE          - L/min (0-1000)
      3x01  TANK_LEVEL         - % (0-100)
      3x02  INLET_PRESSURE     - kPa (0-600)
      3x03  OUTLET_PRESSURE    - kPa (0-600)
      3x04  WATER_TEMP         - °C x10 (e.g. 225 = 22.5°C)
      3x05  TURBIDITY          - NTU x100
      3x06  PH_VALUE           - pH x100 (e.g. 750 = 7.50)
      3x07  CHLORINE_PPM       - ppm x100
      3x08  PUMP1_CURRENT      - mA
      3x09  PUMP2_CURRENT      - mA
      3x10  RUNTIME_HOURS      - hours

    HOLDING REGISTERS (Read/Write 16-bit) - 4x (addresses 0-19):
      4x00  PUMP1_SETPOINT     - Target flow L/min
      4x01  TANK_LEVEL_HI      - High level alarm setpoint %
      4x02  TANK_LEVEL_LO      - Low level alarm setpoint %
      4x03  PRESSURE_MAX       - Max pressure setpoint kPa
      4x04  CHLORINE_SETPOINT  - Target chlorine ppm x100
      4x05  PH_SETPOINT_HI     - High pH alarm x100
      4x06  PH_SETPOINT_LO     - Low pH alarm x100
      4x07  TEMP_SETPOINT      - Target temp °C x10
      4x08  DOSING_RATE        - Chlorine dosing rate %
      4x09  MAINTENANCE_CODE   - Maintenance access code (VULN: stored in plain)
      4x10  SYSTEM_MODE        - 0=Auto 1=Manual 2=Maintenance 3=Emergency
      4x11  MODBUS_UNIT_ID     - Configurable unit ID (default 1)
    """

    def __init__(self):
        self.lock = threading.Lock()

        # Coils [0-9]
        self.coils = [
            True,   # 0: PUMP_1_RUN
            False,  # 1: PUMP_2_RUN
            True,   # 2: VALVE_INLET_OPEN
            True,   # 3: VALVE_OUTLET_OPEN
            True,   # 4: CHLORINE_DOSING
            True,   # 5: UV_STERILIZER
            False,  # 6: ALARM_ACTIVE
            False,  # 7: EMERGENCY_STOP
            False,  # 8: PUMP_3_RUN
            False,  # 9: HEATER_ON
        ]

        # Discrete inputs [0-4] - read only
        self.discrete_inputs = [True, True, True, True, True]

        # Input registers [0-10] - read only (updated by simulation)
        self.input_registers = [
            450,   # 0: FLOW_RATE
            72,    # 1: TANK_LEVEL
            280,   # 2: INLET_PRESSURE
            220,   # 3: OUTLET_PRESSURE
            225,   # 4: WATER_TEMP (22.5C)
            45,    # 5: TURBIDITY (0.45 NTU)
            750,   # 6: PH_VALUE (7.50)
            120,   # 7: CHLORINE_PPM (1.20 ppm)
            1850,  # 8: PUMP1_CURRENT
            0,     # 9: PUMP2_CURRENT
            1432,  # 10: RUNTIME_HOURS
        ]

        # Holding registers [0-11] - read/write
        self.holding_registers = [
            500,   # 0: PUMP1_SETPOINT
            85,    # 1: TANK_LEVEL_HI
            15,    # 2: TANK_LEVEL_LO
            500,   # 3: PRESSURE_MAX
            150,   # 4: CHLORINE_SETPOINT
            800,   # 5: PH_SETPOINT_HI (8.00)
            650,   # 6: PH_SETPOINT_LO (6.50)
            230,   # 7: TEMP_SETPOINT (23.0C)
            65,    # 8: DOSING_RATE
            0xDEAD,# 9: MAINTENANCE_CODE ← VULNERABLE: hardcoded 0xDEAD
            0,     # 10: SYSTEM_MODE (0=Auto)
            1,     # 11: MODBUS_UNIT_ID
        ]

        self.write_log = []
        self.request_count = 0

    def simulate_process(self):
        """Simulate realistic process noise on sensor values."""
        with self.lock:
            # Only simulate if not in emergency stop
            if self.coils[7]:  # EMERGENCY_STOP
                self.coils[0] = False
                self.coils[1] = False
                self.coils[6] = True
                self.input_registers[0] = 0   # flow drops
                self.input_registers[8] = 0
                self.input_registers[9] = 0
                return

            # Pump 1 affects flow
            if self.coils[0]:
                target = self.holding_registers[0]
                current = self.input_registers[0]
                self.input_registers[0] = int(current + (target - current) * 0.1 + random.randint(-5, 5))
                self.input_registers[8] = random.randint(1800, 1950)
            else:
                self.input_registers[0] = max(0, self.input_registers[0] - random.randint(10, 30))
                self.input_registers[8] = 0

            # Tank level drifts based on inlet/outlet
            inlet = 1 if self.coils[2] else 0
            outlet = 1 if self.coils[3] else 0
            delta = (inlet - outlet) * random.uniform(0.05, 0.15)
            self.input_registers[1] = max(0, min(100, self.input_registers[1] + delta))

            # Chlorine dosing affects ppm
            if self.coils[4]:
                rate = self.holding_registers[8]
                self.input_registers[7] = int(self.holding_registers[4] * (rate / 100.0) + random.randint(-5, 5))
            else:
                self.input_registers[7] = max(0, self.input_registers[7] - random.randint(1, 5))

            # pH drifts
            ph = self.input_registers[6]
            ph += random.randint(-3, 3)
            self.input_registers[6] = max(600, min(850, ph))

            # Turbidity varies
            self.input_registers[5] = max(1, min(500, self.input_registers[5] + random.randint(-2, 3)))

            # Pressure
            if self.coils[0]:
                self.input_registers[2] = random.randint(270, 295)
                self.input_registers[3] = random.randint(215, 230)
            else:
                self.input_registers[2] = random.randint(0, 20)
                self.input_registers[3] = random.randint(0, 10)

            # Temperature
            t = self.input_registers[4]
            self.input_registers[4] = max(150, min(350, t + random.randint(-1, 1)))

            # Runtime
            self.input_registers[10] += 1 if random.random() < 0.01 else 0

            # Check alarms
            level = self.input_registers[1]
            if level > self.holding_registers[1] or level < self.holding_registers[2]:
                self.coils[6] = True
            elif self.input_registers[3] > self.holding_registers[3]:
                self.coils[6] = True
            else:
                if not self.coils[7]:
                    self.coils[6] = False

    def log_write(self, fc, addr, value, unit_id):
        entry = {
            "time": datetime.now().isoformat(),
            "fc": f"0x{fc:02X}",
            "address": addr,
            "value": value,
            "unit_id": unit_id
        }
        self.write_log.append(entry)
        if len(self.write_log) > 500:
            self.write_log.pop(0)
        log.warning(f"[WRITE] FC={fc:02X} addr={addr} val={value} unit={unit_id}")


# ── Modbus TCP Protocol Handler ───────────────────────────────────────────────

class ModbusTCPHandler:
    MBAP_HEADER_SIZE = 6

    # Exception codes
    EX_ILLEGAL_FUNCTION     = 0x01
    EX_ILLEGAL_DATA_ADDRESS = 0x02
    EX_ILLEGAL_DATA_VALUE   = 0x03
    EX_SERVER_DEVICE_FAILURE= 0x04

    def __init__(self, datastore):
        self.ds = datastore

    def build_exception(self, tid, unit_id, fc, exc_code):
        pdu = struct.pack('BB', fc | 0x80, exc_code)
        mbap = struct.pack('>HHHB', tid, 0, len(pdu) + 1, unit_id)
        return mbap + pdu

    def build_response(self, tid, unit_id, pdu):
        mbap = struct.pack('>HHHB', tid, 0, len(pdu) + 1, unit_id)
        return mbap + pdu

    def handle(self, data):
        if len(data) < self.MBAP_HEADER_SIZE + 1:
            return None

        tid, proto_id, length, unit_id = struct.unpack('>HHHB', data[:7])
        if proto_id != 0:
            return None

        fc = data[7]
        payload = data[8:]
        self.ds.request_count += 1

        # FC 01 - Read Coils
        if fc == 0x01:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack('>HH', payload[:4])
            with self.ds.lock:
                coils = self.ds.coils
            if start + count > len(coils):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            byte_count = (count + 7) // 8
            coil_bytes = bytearray(byte_count)
            for i in range(count):
                if coils[start + i]:
                    coil_bytes[i // 8] |= (1 << (i % 8))
            pdu = struct.pack('BB', fc, byte_count) + bytes(coil_bytes)
            return self.build_response(tid, unit_id, pdu)

        # FC 02 - Read Discrete Inputs
        elif fc == 0x02:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack('>HH', payload[:4])
            with self.ds.lock:
                di = self.ds.discrete_inputs
            if start + count > len(di):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            byte_count = (count + 7) // 8
            di_bytes = bytearray(byte_count)
            for i in range(count):
                if di[start + i]:
                    di_bytes[i // 8] |= (1 << (i % 8))
            pdu = struct.pack('BB', fc, byte_count) + bytes(di_bytes)
            return self.build_response(tid, unit_id, pdu)

        # FC 03 - Read Holding Registers
        elif fc == 0x03:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack('>HH', payload[:4])
            with self.ds.lock:
                regs = self.ds.holding_registers
            if start + count > len(regs):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            byte_count = count * 2
            pdu = struct.pack('BB', fc, byte_count)
            for i in range(count):
                pdu += struct.pack('>H', regs[start + i])
            return self.build_response(tid, unit_id, pdu)

        # FC 04 - Read Input Registers
        elif fc == 0x04:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count = struct.unpack('>HH', payload[:4])
            with self.ds.lock:
                regs = self.ds.input_registers
            if start + count > len(regs):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            byte_count = count * 2
            pdu = struct.pack('BB', fc, byte_count)
            for i in range(count):
                pdu += struct.pack('>H', regs[start + i])
            return self.build_response(tid, unit_id, pdu)

        # FC 05 - Write Single Coil (VULNERABLE: no auth, no range check beyond bounds)
        elif fc == 0x05:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            addr, value = struct.unpack('>HH', payload[:4])
            if addr >= len(self.ds.coils):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            coil_val = (value == 0xFF00)
            with self.ds.lock:
                self.ds.coils[addr] = coil_val
            self.ds.log_write(fc, addr, coil_val, unit_id)
            pdu = struct.pack('BB', fc, 0) + payload[:4]
            pdu = struct.pack('B', fc) + payload[:4]
            return self.build_response(tid, unit_id, pdu)

        # FC 06 - Write Single Register (VULNERABLE: maintenance code writable)
        elif fc == 0x06:
            if len(payload) < 4:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            addr, value = struct.unpack('>HH', payload[:4])
            if addr >= len(self.ds.holding_registers):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                self.ds.holding_registers[addr] = value
            self.ds.log_write(fc, addr, value, unit_id)
            pdu = struct.pack('B', fc) + payload[:4]
            return self.build_response(tid, unit_id, pdu)

        # FC 0F (15) - Write Multiple Coils
        elif fc == 0x0F:
            if len(payload) < 5:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count, byte_count = struct.unpack('>HHB', payload[:5])
            coil_data = payload[5:5 + byte_count]
            if start + count > len(self.ds.coils):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                for i in range(count):
                    bit = (coil_data[i // 8] >> (i % 8)) & 1
                    self.ds.coils[start + i] = bool(bit)
            self.ds.log_write(fc, start, f"{count} coils", unit_id)
            pdu = struct.pack('>BHH', fc, start, count)
            return self.build_response(tid, unit_id, pdu)

        # FC 10 (16) - Write Multiple Registers (VULNERABLE: bulk process override)
        elif fc == 0x10:
            if len(payload) < 5:
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_VALUE)
            start, count, byte_count = struct.unpack('>HHB', payload[:5])
            reg_data = payload[5:5 + byte_count]
            if start + count > len(self.ds.holding_registers):
                return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_DATA_ADDRESS)
            with self.ds.lock:
                for i in range(count):
                    val = struct.unpack('>H', reg_data[i*2:(i+1)*2])[0]
                    self.ds.holding_registers[start + i] = val
            self.ds.log_write(fc, start, f"{count} regs bulk write", unit_id)
            pdu = struct.pack('>BHH', fc, start, count)
            return self.build_response(tid, unit_id, pdu)

        # FC 11 (17) - Report Server ID (VULNERABLE: leaks device info)
        elif fc == 0x11:
            device_id = b'VulnPLC-WTP-001\x00FW:1.0.3\x00Vendor:ACME-ICS\x00'
            pdu = struct.pack('BB', fc, len(device_id) + 1) + b'\xFF' + device_id
            log.warning(f"[INFO LEAK] FC17 - Device ID requested by unit {unit_id}")
            return self.build_response(tid, unit_id, pdu)

        # FC 2B (43) - Read Device Identification (MEI) - VULNERABLE: full info leak
        elif fc == 0x2B:
            mei_data = (
                b'\x2B\x0E\x01\x83\x00\x00\x03'
                b'\x00\x0CVulnPLC-WTP'    # VendorName
                b'\x01\x09ACME-ICS-1'     # ProductCode
                b'\x02\x051.0.3'          # MajorMinorRevision
            )
            pdu = bytes([fc]) + mei_data
            log.warning(f"[INFO LEAK] FC43 MEI - Device identification read")
            return self.build_response(tid, unit_id, pdu)

        else:
            log.warning(f"[FC] Unsupported function code 0x{fc:02X}")
            return self.build_exception(tid, unit_id, fc, self.EX_ILLEGAL_FUNCTION)


# ── TCP Server ────────────────────────────────────────────────────────────────

class ModbusTCPServer:
    def __init__(self, host='0.0.0.0', port=502, datastore=None):
        self.host = host
        self.port = port
        self.ds = datastore or PLCDataStore()
        self.handler = ModbusTCPHandler(self.ds)
        self.running = False

    def handle_client(self, conn, addr):
        log.info(f"[CONNECT] {addr[0]}:{addr[1]}")
        try:
            conn.settimeout(30)
            while self.running:
                data = b''
                # Read MBAP header first
                try:
                    header = conn.recv(6)
                    if not header:
                        break
                    if len(header) < 6:
                        break
                    length = struct.unpack('>H', header[4:6])[0]
                    body = conn.recv(length)
                    if not body:
                        break
                    data = header + body
                except socket.timeout:
                    break
                except Exception:
                    break

                if not data:
                    break

                response = self.handler.handle(data)
                if response:
                    conn.sendall(response)
        except Exception as e:
            log.debug(f"Client {addr} error: {e}")
        finally:
            conn.close()
            log.info(f"[DISCONNECT] {addr[0]}:{addr[1]}")

    def start(self):
        self.running = True
        # Start process simulation thread
        sim_thread = threading.Thread(target=self._simulation_loop, daemon=True)
        sim_thread.start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host, self.port))
        except PermissionError:
            log.warning(f"Port {self.port} requires root. Trying 5020...")
            self.port = 5020
            srv.bind((self.host, self.port))

        srv.listen(10)
        log.info(f"╔══════════════════════════════════════════════╗")
        log.info(f"║  Modbus TCP PLC Simulator ONLINE             ║")
        log.info(f"║  Address : {self.host}:{self.port:<5}                    ║")
        log.info(f"║  Process : Water Treatment Plant             ║")
        log.info(f"║  Unit ID : 1 (default)                       ║")
        log.info(f"╚══════════════════════════════════════════════╝")
        log.info(f"[VULN] No authentication - all writes accepted")
        log.info(f"[VULN] FC11/FC43 device info disclosure enabled")
        log.info(f"[VULN] Maintenance code at HR[9] = 0xDEAD")

        try:
            while self.running:
                conn, addr = srv.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            log.info("PLC Simulator shutting down...")
        finally:
            srv.close()

    def _simulation_loop(self):
        while self.running:
            self.ds.simulate_process()
            time.sleep(1)


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 502
    ds = PLCDataStore()
    server = ModbusTCPServer(port=port, datastore=ds)
    server.start()
