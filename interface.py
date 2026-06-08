import os
import time
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from prompt_toolkit.shortcuts import radiolist_dialog, input_dialog
from prompt_toolkit.styles import Style
from Crypto.PublicKey import RSA

from connection import HardwareToken
from encryption import OpenBoxCrypto
from image_hide import IWTStego

console = Console()
black_theme = Style.from_dict({
    'dialog': 'bg:#000000 #ffffff',
    'dialog.body': 'bg:#000000 #cccccc',
    'button.focused': 'bg:#ffffff #000000 bold',
    'radio-selected': 'bg:#ffffff #000000',
})

SERVER_URL = "http://127.0.0.1:5000"
CACHE_DIR = "key_cache"

class OpenBoxTUI:
    def __init__(self):
        self.stego = IWTStego()
        self.current_user = None
        self.current_priv_key = None
        
        if not os.path.exists(CACHE_DIR):
            os.makedirs(CACHE_DIR)

    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def resolve_public_key(self, username: str) -> str:
        """Dynamic Discovery Engine: Pulls from cache first, falls back to server lookup."""
        cache_path = os.path.join(CACHE_DIR, f"{username}_public.pem")
        if os.path.exists(cache_path):
            return cache_path

        try:
            response = requests.get(f"{SERVER_URL}/lookup/{username}", timeout=3)
            if response.status_code == 200:
                pub_key_data = response.json().get("public_key")
                with open(cache_path, "w") as f:
                    f.write(pub_key_data)
                return cache_path
        except Exception as e:
            console.print(f"\n[red]PKI Server communication failure: {e}[/red]")
        return None

    def enforce_authentication(self) -> bool:
        """Gating Routine: Requires registration or login before granting access."""
        while not self.current_user:
            self.clear()
            choice = radiolist_dialog(
                title="OpenBox Access Control System",
                text="Authentication required to mount secure modules:",
                values=[
                    ("login",    "Sign In (Existing Identity)"),
                    ("register", "Register (Generate Keys & Secure Identity)"),
                    ("exit",     "Terminate Application")
                ], style=black_theme
            ).run()

            if choice == "exit" or choice is None:
                return False

            elif choice == "register":
                username = input_dialog(title="Registration", text="Choose a unique username:", style=black_theme).run()
                if not username: continue
                password = input_dialog(title="Registration", text="Choose a secure password:", password=True, style=black_theme).run()
                if not password: continue

                self.clear()
                console.print("[cyan][*] Generating RSA-2048 keypairs locally...[/cyan]")
                priv_path, pub_path = OpenBoxCrypto.generate_rsa_keys(username)
                
                with open(pub_path, "r") as f:
                    public_key_pem = f.read()

                try:
                    payload = {"username": username, "password": password, "public_key": public_key_pem}
                    res = requests.post(f"{SERVER_URL}/register", json=payload, timeout=5)
                    if res.status_code == 201:
                        console.print(f"\n[green][+] Account created. Private key isolated at: {priv_path}[/green]")
                        
                        # Mandated Security Warning Prompt
                        console.print("\n[bold red]==================================================================[/bold red]")
                        console.print("[bold yellow][!] SECURITY WARNING: Private Key (.pem) file is generated, do not share it with anyone.[/bold yellow]")
                        console.print("[bold red]==================================================================[/bold red]")
                        input("\nPress Enter to acknowledge and continue...")

                        with open(os.path.join(CACHE_DIR, f"{username}_public.pem"), "w") as f:
                            f.write(public_key_pem)
                        time.sleep(1)
                    else:
                        console.print(f"\n[red][-] Server rejected registration: {res.json().get('error')}[/red]")
                        time.sleep(3)
                except Exception as e:
                    console.print(f"\n[red][-] Unable to reach PKI Server: {e}[/red]")
                    time.sleep(3)

            elif choice == "login":
                username = input_dialog(title="Login", text="Enter username:", style=black_theme).run()
                if not username: continue
                password = input_dialog(title="Login", text="Enter password:", password=True, style=black_theme).run()
                if not password: continue

                # New Security Step: Prompt for explicit private key path file assignment
                priv_key_path = input_dialog(
                    title="Login - Security Step", 
                    text="Enter the local file path to your Private Key (.pem):", 
                    default=f"{username}_private.pem",
                    style=black_theme
                ).run()
                if not priv_key_path: continue

                # Check if the private key file exists
                if not os.path.exists(priv_key_path):
                    input(f"\n[red]Security Halt: Private key file not found at '{priv_key_path}'. Press Enter...[/red]")
                    continue

                # Structure Verification: Import and check if it's a valid asymmetric private key string
                try:
                    with open(priv_key_path, "r") as f:
                        key_data = f.read()
                    parsed_key = RSA.import_key(key_data)
                    if not parsed_key.has_private():
                        raise ValueError("The selected PEM file does not contain a private key component.")
                except Exception as e:
                    input(f"\n[red]Security Halt: Structural key verification failed ({e}). Press Enter...[/red]")
                    continue

                try:
                    payload = {"username": username, "password": password}
                    res = requests.post(f"{SERVER_URL}/login", json=payload, timeout=5)
                    if res.status_code == 200:
                        self.current_user = username
                        self.current_priv_key = priv_key_path  # Binds verified path directly to session
                        console.print(f"\n[green][+] Authentication passed. Welcome, {username}.[/green]")
                        time.sleep(1.5)
                        return True
                    else:
                        input(f"\n[red][-] Authentication failed: {res.json().get('error')}. Press Enter...[/red]")
                except Exception as e:
                    input(f"\n[red][-] Authentication server offline: {e}. Press Enter...[/red]")
        return True

    def run(self):
        if not self.enforce_authentication():
            return

        while True:
            self.clear()
            action = radiolist_dialog(
                title=f"OpenBox Studio | Session: {self.current_user}",
                text="Select System Operation:",
                values=[
                    ("encrypt",  "Protocol: Encrypt & Embed Data"),
                    ("decrypt",  "Protocol: Extract & Verify Image"),
                    ("logout",   "Log Out Session"),
                    ("exit",     "Exit")
                ], style=black_theme
            ).run()

            if action == "encrypt": self.encrypt_flow()
            elif action == "decrypt": self.decrypt_flow()
            elif action == "logout":
                self.current_user = None
                self.current_priv_key = None
                if not self.enforce_authentication(): break
            else: break

    def encrypt_flow(self):
        hw_mode = radiolist_dialog(
            title="HSM Auth", text="Select Token Interface:",
            values=[("USB", "Direct Serial Link"), ("LAN", "Wireless Sub-net")],
            style=black_theme).run()
        if not hw_mode: return
        
        target_ip = None
        if hw_mode == "LAN":
            target_ip = input_dialog(title="LAN Setup", text="Enter ESP32 IP:", style=black_theme).run()
            
        hsm = HardwareToken(mode=hw_mode, target_ip=target_ip)
        if not hsm.connect():
            input("\n[red]Hardware connection failed. Press Enter...[/red]")
            return

        target_username = input_dialog(title="Target Identity", text="Enter Receiver's Username:", style=black_theme).run()
        if not target_username: return
        
        rec_pub_path = self.resolve_public_key(target_username)
        if not rec_pub_path:
            input(f"\n[red][-] Error: Could not resolve public key for user '{target_username}'. Press Enter...[/red]")
            return

        img_path = input_dialog(title="Carrier", text="Image path:", style=black_theme).run()
        text = input_dialog(title="Payload", text="Text or .txt path:", style=black_theme).run()
        if not img_path or not text: return
        
        if os.path.exists(text) and text.endswith('.txt'): 
            text = open(text).read()
        
        seed = hsm.request_seed()
        hsm.close()

        self.clear()
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), BarColumn(), console=console) as p:
            crypto = OpenBoxCrypto(seed)
            t1 = p.add_task("Encrypting & Signing Payload...", total=100)
            enc_seed, sig, nonce, tag, ct = crypto.encrypt_payload(text, rec_pub_path, self.current_priv_key)
            p.update(t1, advance=100)

            t2 = p.add_task("Applying Discrete Wavelet Transforms...", total=100)
            self.stego.embed(img_path, enc_seed, sig, nonce, tag, ct, crypto, "stego_out.png")
            p.update(t2, advance=100)

        console.print("\n[bold green]SUCCESS: Secured Image generated -> stego_out.png[/bold green]")
        input("\nPress Enter...")

    def decrypt_flow(self):
        img_path = input_dialog(title="Extraction", text="Stego Image path:", style=black_theme).run()
        sender_username = input_dialog(title="Verify", text="Enter Sender's Username:", style=black_theme).run()
        if not img_path or not sender_username: return

        sender_pub_path = self.resolve_public_key(sender_username)
        if not sender_pub_path:
            input(f"\n[red][-] Error: Could not resolve public key for user '{sender_username}'. Press Enter...[/red]")
            return

        self.clear()
        with Progress(SpinnerColumn(), TextColumn("[magenta]{task.description}"), BarColumn(), console=console) as p:
            t1 = p.add_task("Parsing IWT Frequencies...", total=100)
            ct_len, enc_seed, sig, hh_flat = self.stego.extract(img_path, crypto=None)
            p.update(t1, advance=100)

            t2 = p.add_task("Hardware Verification & Cryptographic Unpacking...", total=100)
            try:
                crypto = OpenBoxCrypto()
                nonce, tag, ct = self.stego.extract_chaotic_payload(hh_flat, ct_len, crypto)
                plaintext = crypto.decrypt_payload(enc_seed, sig, nonce, tag, ct, self.current_priv_key, sender_pub_path)
                p.update(t2, advance=100)
                
                console.print("\n[bold green]DOCUMENT AUTHENTICATED & EXTRACTED[/bold green]")
                console.print(Panel(plaintext, border_style="green"))
            except ValueError as e:
                console.print(f"\n[bold red]SECURITY HALT: {e}[/bold red]")
        input("\nPress Enter...")

if __name__ == "__main__":
    OpenBoxTUI().run()