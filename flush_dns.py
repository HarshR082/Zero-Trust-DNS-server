import subprocess

def clear_windows_dns_cache():
    subprocess.run("ipconfig /flushdns", shell=True)
    print("✅ Flushed Windows DNS cache.")

clear_windows_dns_cache()
