import time
import serial
import socket
import serial.tools.list_ports as available_ports

class HardwareToken:
    def __init__(self, mode='USB', target_ip=None, b_rate=115200):
        self.mode = mode.upper()
        self.target_ip = target_ip
        self.b_rate = b_rate
        self.connection = None

    def connect(self) -> bool:
        """Establishes connection based on the selected mode."""
        if self.mode == 'USB':
            ports = available_ports.comports()
            port = next((p.device for p in ports if "USB" in p.description or "ACM" in p.device), None)
            if not port:
                print("[-] No HSM detected on USB ports.")
                return False
            self.connection = serial.Serial(port, self.b_rate, timeout=2)
            time.sleep(2)  # Allow bootloader to settle
            return self._ping_usb()
            
        elif self.mode == 'LAN':
            if not self.target_ip:
                print("[-] LAN mode requires a target IP.")
                return False
            return self._ping_lan()
        return False

    def _ping_usb(self) -> bool:
        try:
            self.connection.reset_input_buffer()
            self.connection.write(b'P')
            return self.connection.readline().decode().strip() == "PONG"
        except Exception:
            return False

    def _ping_lan(self) -> bool:
        try:
            with socket.create_connection((self.target_ip, 8888), timeout=2) as sock:
                sock.sendall(b'P')
                return sock.recv(1024).decode().strip() == "PONG"
        except Exception:
            return False

    def request_seed(self) -> bytes:
        """Retrieves 32-byte physical entropy from the ESP32."""
        try:
            if self.mode == 'USB':
                self.connection.reset_input_buffer()
                self.connection.write(b'K')
                resp = self.connection.readline().decode().strip()
            else:
                with socket.create_connection((self.target_ip, 8888), timeout=3) as sock:
                    sock.sendall(b'K')
                    resp = sock.recv(1024).decode().strip()
                    
            if len(resp) == 64:
                return bytes.fromhex(resp)
            raise ValueError("Malformed hardware seed.")
        except Exception as e:
            print(f"[-] Hardware Error: {e}")
            return None

    def close(self):
        if self.mode == 'USB' and self.connection:
            self.connection.close()