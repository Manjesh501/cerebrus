import os
import shutil

def create_persistence():
    startup_folder = os.path.join(
        os.environ["APPDATA"],
        "Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    )
    payload_path = os.path.join(startup_folder, "hello_demo.py")

    with open(payload_path, "w") as f:
        f.write('import time\n')
        f.write('print("Hello, Malware Demo (Windows)")\n')
        f.write('time.sleep(5)\n')

    print(f"[+] Persistence added via Startup Folder. Payload: {payload_path}")

if __name__ == "__main__":
    create_persistence()
