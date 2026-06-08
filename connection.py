import time
import serial 
import serial.tools.list_ports as available_ports


class HardwareToken:
    def __init__(self, b_rate = 115200, timeout = 2):
        self.b_rate = b_rate
        self.timeout = timeout
        self.connection = None
        self.port = self._find_esp32_port()

    def _find_esp32_port(self):
        """Scans the system's ports to find an available serial connection.
        The main funciton's return is `port` or `None`."""
        ports = available_ports.comports()
        for p in ports: 
            if "CP210" in p.description or "CH340" in p.description or "USB" in p.description:
                print(f"Port Connected {p}")
                return p.device

        return ports[0].device if ports else None

    def connect(self):
        """Connects the system with ESP32 with the available serial connection."""
        if not self.port:
            raise serial.SerialException("No viable USB serial device detected. Plug-in the chip first.")

        print(f"Connecting to hardware token on port: {self.port}")
        self.connection = serial.Serial(self.port, self.b_rate, timeout=self.timeout)

        time.sleep(2)
        return self.verify_token()

    def verify_token(self):
        """Sends a physical challenge ping to authenticate the hardware component."""
        if not self.connection or not self.connection.is_open:
            return False

        try: 
            self.connection.reset_input_buffer()
            self.connection.write(b'P')
            response = self.connection.readline().decode('utf-8').strip()

            if response == "AUTHENTICATED_CONNECTED":
                print("Hardware token authenticated successfully!")
                return True
            return False

        except Exception as e:
            print(f"Authentication Failed! Please Try Again...")
            return False

    def request_hardware_seed(self):
        """Requests a 32-byte true random key from the chip's TRNG"""
        if not self.connection or not self.connection.is_open:
            raise ConnectionError("Hardware token is not connected or verified...")

        try: 
            self.connection.reset_input_buffer()

            self.connection.write(b'K')
            hex_response = self.connection.readline().decode('utf-8').strip()

            if len(hex_response) == 64 and all(c in '01234567890abcdefABCDEF' for c in hex_response):
                return bytes.fromhex(hex_response)

            else: 
                raise ValueError(f"WARNING: Malformed key payload recieved: {hex_response}")
        
        except Exception as e:
            print(f"Failed to extract hardware seed {e}")
            return None

    def close(self):
        """Close the connection stream."""

        if self.connection and self.connection.is_open:
            self.connection.close()
            print("Hardware link closed successfully.")

if __name__ == "__main__":
    token = HardwareToken()
    try: 
        if token.connect():
            raw_key = token.request_hardware_seed()
            if raw_key:
                print(f"SUCCESS: Hardware seed acquired (Length {len(raw_key)})")
                print(f"Hex Representation: {raw_key.hex().upper()}")
    except Exception as e:
        print(f"FAILED: {e}")
    finally:
        token.close()

