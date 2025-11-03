#!/usr/bin/env python3
"""
ZephyrusRecon Kali Linux - Recon pipeline with Discord real-time updates + colored terminal + partial nuclei streaming (httpx real filter)
Author: Zephyrus
Version: v1.3.4-kali
"""

import os, sys, subprocess, shutil, time, json, argparse, re, tempfile
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from collections import Counter

# ----- CONFIG -----
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1434645581413879868/AXG3p-2f4t1fb-WqZ3ZAN9K2ctJllobCIHasSQyBPd5_G8fPkgyc8nV5C0vIp-cDJkP6"
REQUIRED_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
}
PY_DEPS = ["requests", "beautifulsoup4", "pyfiglet", "colorama"]

# ----- Banner -----
def print_banner():
    try:
        from pyfiglet import Figlet
        f = Figlet(font='slant')
        print(f.renderText('ZephyrusRecon'))
        print("                     v1.3.4-kali | Author: Zephyrus\n")
    except ImportError:
        print("ZephyrusRecon v1.3.4-kali | Author: Zephyrus\n")

# ----- Terminal color -----
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = ""; GREEN = ""; YELLOW = ""; BLUE = ""; MAGENTA = ""; CYAN = ""
    class Style:
        RESET_ALL = ""

def cprint(msg, color=Fore.GREEN):
    print(f"{color}{msg}{Style.RESET_ALL}")

# ----- Helpers -----
def which(cmd): return shutil.which(cmd) is not None

def run(cmd, capture=True, timeout=None, shell=False):
    try:
        if capture:
            completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, shell=shell)
            return completed.returncode, completed.stdout, completed.stderr
        else:
            completed = subprocess.run(cmd, check=False, timeout=timeout, shell=shell)
            return completed.returncode, "", ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def ensure_python_deps():
    missing=[]
    for pkg in PY_DEPS:
        try: __import__(pkg)
        except Exception: missing.append(pkg)
    if not missing: return True
    cprint(f"[*] Installing python deps: {missing}", Fore.YELLOW)
    rc,_,_=run([sys.executable,"-m","pip","install"]+missing, timeout=300)
    return rc==0

def ensure_go():
    if which("go"): return True
    cprint("[!] 'go' not found. Installing via apt ...", Fore.RED)
    run(["sudo","apt","update"], timeout=300)
    run(["sudo","apt","install","-y","golang"], timeout=600)
    return which("go")

def go_install(pkg):
    cprint(f"[*] Installing {pkg} via go install...", Fore.CYAN)
    rc,_,_=run(["go","install",pkg], timeout=600)
    return rc==0

def ensure_tools_auto():
    installed=[]; failed={}
    if not ensure_python_deps(): failed["python_deps"]="pip failed"
    need=[t for t in REQUIRED_TOOLS if not which(t)]
    if need and not ensure_go(): failed["go"]="missing"
    for t in need:
        if go_install(REQUIRED_TOOLS[t]): installed.append(t)
        else: failed[t]="install failed"
    return installed, failed

# ----- Discord -----
def send_discord_embed(title, desc, color=0x2ecc71):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL: return False,"no webhook"
    payload={"username":"ZephyrusRecon","embeds":[{"title":title,"description":desc,"color":color}]}
    try:
        r=requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=15)
        return r.status_code in (200,204), r.text
    except Exception as e:
        return False, str(e)

def send_discord_file(file_path, content=None, filename=None):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL: return False,"no webhook"
    if filename is None: filename=os.path.basename(file_path)
    try:
        with open(file_path,"rb") as f:
            data={}
            if content: data["payload_json"]=json.dumps({"content":content})
            r=requests.post(DISCORD_WEBHOOK_URL, files={"file":(filename,f)}, data=data, timeout=90)
        return r.status_code in (200,204), r.text
    except Exception as e:
        return False, str(e)

# ----- File utils -----
def read_lines(path):
    try: return [l.strip() for l in open(path,"r",encoding="utf-8") if l.strip()]
    except: return []

def strip_scheme(urls):
    return [u[8:] if u.startswith("https://") else u[7:] if u.startswith("http://") else u for u in urls]

# ----- Tool wrappers -----
def run_subfinder(domain, out_path): return run(["subfinder","-d",domain,"-o",out_path], timeout=600)
def run_wayback(domain, out_path): return run(["bash","-lc",f"echo {domain}|waybackurls 2>/dev/null|tee {out_path}"], timeout=300, shell=True)
def run_katana(hosts_file, out_file): return run(["katana","-list",hosts_file,"-depth","2","-o",out_file], timeout=1800)

# ----- HTTPX wrapper (fixed - use -list) -----
def run_httpx_toolkit_on_list(list_lines, threads=50, timeout_s=10, status_codes=None):
    bin_name = "httpx"
    if not which(bin_name):
        return 1, "", f"{bin_name} not found in PATH"

    tmp_in = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
    tmp_out = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
    tmp_in_path = tmp_in.name
    tmp_out_path = tmp_out.name
    try:
        for u in list_lines:
            if u:
                tmp_in.write(u.strip() + "\n")
        tmp_in.flush()
        tmp_in.close()
        tmp_out.close()

        # ✅ FIXED: gunakan -list, bukan -l
        cmd = [
            bin_name,
            "-list", tmp_in_path,
            "-silent",
            "-timeout", str(timeout_s),
            "-threads", str(threads),
            "-o", tmp_out_path
        ]
        if status_codes:
            cmd.extend(["-mc", ",".join(map(str, status_codes))])

        rc, out, err = run(cmd, capture=True, timeout=900)
        alive = []
        if os.path.exists(tmp_out_path):
            alive = read_lines(tmp_out_path)
        else:
            alive = [l.strip() for l in out.splitlines() if l.strip()]

        os.remove(tmp_in_path)
        os.remove(tmp_out_path)

        return rc, "\n".join(alive), err or ""
    except Exception as e:
        os.remove(tmp_in_path)
        os.remove(tmp_out_path)
        return 1, "", str(e)

# ----- Nuclei streaming (10 min heartbeat) -----
def run_nuclei_stream(urls_file, out_file, severity="critical,high,medium", periodic_upload=True, interval_seconds=600):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    cmd = ["nuclei", "-l", urls_file, "-severity", severity]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    buffer_lines = []
    start_time = time.time()
    last_upload = start_time
    with open(out_file, "w", encoding="utf-8") as fout:
        for line in proc.stdout:
            clean_line = ansi_escape.sub('', line.strip())
            if not clean_line:
                continue
            fout.write(clean_line + "\n")
            fout.flush()
            buffer_lines.append(clean_line)
            if periodic_upload and (time.time() - last_upload) >= interval_seconds:
                send_discord_file(out_file, f"Partial nuclei output ({len(buffer_lines)} new findings)")
                last_upload = time.time()
                buffer_lines.clear()
        proc.wait()
    if periodic_upload:
        send_discord_file(out_file, "Final nuclei output (scan completed)")
    return {"stdout": "nuclei finished"}

def send_nuclei_summary(out_file, workdir, target):
    lines = read_lines(out_file)
    severity_counts = Counter()
    for l in lines:
        if "[" in l and "]" in l:
            sev_part = l.split("[")[-1].split("]")[0]
            severity_counts[sev_part] += 1
    summary = (
        f"🏁 SCAN COMPLETED\nWorkdir: {workdir}\nTarget: {target}\n"
        f"Findings: {len(lines)}\n"
        f"Severity\n"
        f"🔴C:{severity_counts.get('critical',0)} "
        f"🟠H:{severity_counts.get('high',0)} "
        f"🟡M:{severity_counts.get('medium',0)} "
        f"🔵L:{severity_counts.get('low',0)} "
        f"ℹ️I:{severity_counts.get('info',0)}"
    )
    send_discord_embed("Nuclei Scan Summary", summary)

# ----- Pipeline -----
def pipeline_for_domain(domain, workdir:Path, args):
    workdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_sub = workdir / f"subfinder_{ts}.txt"
    out_way = workdir / f"wayback_{ts}.txt"
    out_kat = workdir / f"katana_{ts}.txt"
    out_nuc = workdir / f"nuclei_output_{ts}.txt"

    cprint(f"🚀 Starting scan for {domain}", Fore.CYAN)
    send_discord_embed("🚀 RECON SCAN STARTED", f"Target: {domain}\nSteps: subfinder → HTTPX → Wayback → Katana → Nuclei")

    send_discord_embed("⚪ Subfinder", f"Running subfinder for {domain}")
    run_subfinder(domain, str(out_sub))
    subs = read_lines(str(out_sub))
    cprint(f"Subfinder found {len(subs)} subdomains", Fore.GREEN)
    send_discord_file(str(out_sub), f"Subfinder Results ({len(subs)})")

    send_discord_embed("🌐 HTTPX", "Checking alive hosts...")
    rc, stdout, stderr = run_httpx_toolkit_on_list(subs, threads=50, timeout_s=10)
    if rc != 0 and not stdout:
        send_discord_embed("⚠️ HTTPX failed", f"httpx returned rc={rc}. Error: {stderr or 'no output'}. Falling back to unfiltered list.")
        alive = subs
    else:
        alive = stdout.splitlines()
    tmp_alive_file = workdir / f"alive_httpx_{ts}.txt"
    with open(tmp_alive_file, "w", encoding="utf-8") as f:
        f.write("\n".join(alive))
    cprint(f"HTTPX found {len(alive)} alive hosts", Fore.GREEN)
    send_discord_file(str(tmp_alive_file), f"HTTPX Alive Hosts ({len(alive)})")

    send_discord_embed("📚 Wayback", "Collecting Wayback URLs ...")
    run_wayback(domain, str(out_way))
    wayback = read_lines(str(out_way))
    cprint(f"Wayback URLs collected: {len(wayback)}", Fore.GREEN)

    combined = set(wayback)
    send_discord_embed("🕷️ Katana", "Crawling with Katana ...")
    tmp_hosts = workdir / f"kat_hosts_{ts}.txt"
    with open(tmp_hosts, "w", encoding="utf-8") as f:
        f.write("\n".join(alive))
    run_katana(str(tmp_hosts), str(out_kat))
    kat = read_lines(str(out_kat))
    combined.update(kat)
    cprint(f"Katana URLs collected: {len(kat)}", Fore.GREEN)

    nuclei_input = kat or wayback or alive
    tmp_list = workdir / f"nuclei_list_{ts}.txt"
    with open(tmp_list, "w", encoding="utf-8") as f:
        f.writelines(u + "\n" for u in nuclei_input)

    send_discord_embed("💥 Nuclei Scan", f"Severity: {args.nuclei_severity}")
    run_nuclei_stream(str(tmp_list), str(out_nuc), severity=args.nuclei_severity, periodic_upload=True, interval_seconds=600)
    send_discord_file(str(out_nuc), f"Nuclei results for {domain}")
    send_nuclei_summary(str(out_nuc), workdir, domain)

    cprint(f"🏁 Scan completed for {domain}", Fore.CYAN)
    return {"status": "done"}

# ----- Main -----
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="ZephyrusRecon Kali Linux - Recon pipeline")
    parser.add_argument("--workdir", default="./recon_results")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--nuclei-severity", default="critical,high,medium")
    args = parser.parse_args()
    os.environ["PATH"] += os.pathsep + "/usr/local/go/bin"

    cprint("🛠️ Checking & installing required tools ...", Fore.YELLOW)
    installed, failed = ensure_tools_auto()
    send_discord_embed("🛠️ Tools Status", f"Installed: {installed}\nFailed: {list(failed.keys())}")

    choice = input("Choose mode:\n[1] Single Target\n[2] Multi Target (file)\nSelect 1 or 2: ").strip()
    if choice == "1":
        domain = input("Enter target domain: ").strip()
        Arg = type("Arg", (object,), {})()
        Arg.nuclei_severity = args.nuclei_severity
        workdir = Path(args.workdir) / domain.replace(".", "_")
        pipeline_for_domain(domain, workdir, Arg)
    elif choice == "2":
        list_path = input("Enter path to domains file: ").strip()
        domains = read_lines(list_path)
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures = {ex.submit(pipeline_for_domain, d, Path(args.workdir) / d.replace(".", "_"), type("Arg", (object,), {"nuclei_severity": args.nuclei_severity})()): d for d in domains}
            for fut in as_completed(futures):
                d = futures[fut]
                try:
                    res = fut.result()
                    send_discord_embed("✅ Scan finished", f"{d} status: {res.get('status')}")
                except Exception as e:
                    send_discord_embed("⚠️ Scan error", f"{d} error: {e}")

    cprint("🏁 All tasks finished. Check uploaded files.", Fore.CYAN)

if __name__ == "__main__":
    main()
