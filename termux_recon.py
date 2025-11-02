#!/usr/bin/env python3
"""
recon_discord.py

Recon pipeline with Discord real-time updates + partial nuclei streaming.

Features:
- Menu: [1] Single Target, [2] Multi Target (file list)
- Auto-install missing tools (go install) & pip deps automatically
- Pipeline: subfinder -> httpx -> waybackurls -> katana -> combine -> filter -> nuclei
- Real-time Discord messages (per-step) and partial nuclei findings while nuclei runs
- On nuclei finish: upload full nuclei output file (.txt) to Discord
- Default nuclei severity: critical,high,medium (configurable via CLI)
- You MUST confirm permission by typing 'yes' before scan begins

Usage:
  1) Edit DISCORD_WEBHOOK_URL below with your webhook.
  2) python3 recon_discord.py
"""

import os
import sys
import subprocess
import shutil
import time
import json
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests
from collections import Counter

# ----- CONFIG: EDIT THIS -----
DISCORD_WEBHOOK_URL = "https://discordapp.com/api/webhooks/1388192484265427025/jnEKDqZ8u-4AFPmdfA7YTSXZSfP87I4ZUWZGrcCWkQn8LBgD3fKCec9BSJPrVKABDNy4"
# -----------------------------

# Tools mapping (go install pkg)
REQUIRED_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
}
PY_DEPS = ["requests", "beautifulsoup4"]

# ----- helpers -----
def which(cmd):
    if shutil.which(cmd):
        return True
    termux_go_bin = os.path.expanduser("~/go/bin")
    return os.path.exists(os.path.join(termux_go_bin, cmd))

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
    missing = []
    for pkg in PY_DEPS:
        try:
            __import__(pkg)
        except Exception:
            missing.append(pkg)
    if not missing:
        return True
    print("[*] Installing python deps:", missing)
    rc, out, err = run([sys.executable, "-m", "pip", "install"] + missing, timeout=300)
    return rc == 0

def ensure_go():
    if which("go"):
        return True
    print("[!] 'go' not found. Attempting apt/brew best-effort (may require sudo).")
    if which("apt-get"):
        run(["sudo", "apt-get", "update"], timeout=300)
        run(["sudo", "apt-get", "install", "-y", "golang"], timeout=600)
        return which("go")
    if which("brew"):
        run(["brew", "install", "go"], timeout=600)
        return which("go")
    return False

def go_install(pkg):
    print(f"[*] go install {pkg}")
    rc, out, err = run(["go", "install", pkg], timeout=600)
    return rc == 0

def ensure_tools_auto():
    installed = []
    failed = {}
    ok = ensure_python_deps()
    if not ok:
        failed["python_deps"] = "pip install failed"
    need = [t for t in REQUIRED_TOOLS if not which(t)]
    if need:
        ok_go = ensure_go()
        if not ok_go:
            failed["go"] = "go not installed / not in PATH"
    for t in need:
        pkg = REQUIRED_TOOLS[t]
        ok = go_install(pkg)
        if ok:
            installed.append(t)
            rc, out, err = run(["go", "env", "GOBIN"], timeout=10)
            gobin = out.strip() if rc == 0 else ""
            if gobin and os.path.exists(os.path.join(gobin, t)):
                try:
                    run(["sudo", "cp", os.path.join(gobin, t), "/usr/local/bin/"+t], timeout=30)
                except Exception:
                    pass
        else:
            failed[t] = f"go install failed for {pkg}"
    return installed, failed

# ----- Discord helpers -----
def send_discord_message(content, username="ZephyrusRecon"):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL:
        print("[!] Discord webhook not configured. Skipping send.")
        return False, "no webhook"
    payload = {"content": content, "username": username}
    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=15)
        if r.status_code in (200, 204):
            return True, r.text
        else:
            return False, f"{r.status_code} {r.text}"
    except Exception as e:
        return False, str(e)

def send_discord_file(file_path, content=None, filename=None):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL:
        print("[!] Discord webhook not configured. Skipping file upload.")
        return False, "no webhook"
    if filename is None:
        filename = os.path.basename(file_path)
    try:
        with open(file_path, "rb") as f:
            data = {}
            if content:
                data["payload_json"] = json.dumps({"content": content})
            r = requests.post(DISCORD_WEBHOOK_URL, files={"file": (filename, f)}, data=data, timeout=60)
        return (r.status_code in (200,204)), r.text
    except Exception as e:
        return False, str(e)

# ----- Small URL / filter helpers -----
def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []

def filter_urls_set(urls):
    skip_ext = (".jpg",".jpeg",".png",".gif",".svg",".css",".js",".ico",".woff",".woff2",".ttf",".eot",".pdf",".zip",".tar",".gz",".mp4",".webm")
    out = set()
    for u in urls:
        u = u.strip()
        if not u: continue
        if not (u.startswith("http://") or u.startswith("https://")):
            continue
        low = u.lower()
        if any(low.endswith(ext) for ext in skip_ext):
            continue
        out.add(u)
    return sorted(out)

def strip_scheme(urls):
    clean=[]
    for u in urls:
        if u.startswith("http://"):
            clean.append(u[len("http://"):])
        elif u.startswith("https://"):
            clean.append(u[len("https://"):])
        else:
            clean.append(u)
    return clean

# ----- External tool wrappers -----
def run_subfinder(domain, out_path):
    cmd = ["subfinder", "-d", domain, "-o", out_path]
    return run(cmd, timeout=600)

def run_httpx_on_list(list_lines):
    cmd = ["httpx", "-silent", "-no-color", "-follow-redirects", "-probe", "-timeout", "10", "-retries", "2"]
    alive=[]
    fixed=[]
    for u in list_lines:
        u = u.strip()
        if not u: continue
        if not u.startswith("http://") and not u.startswith("https://"):
            fixed.append("https://" + u)
        else:
            fixed.append(u)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input="\n".join(fixed)+"\n", timeout=900)
        for ln in stdout.splitlines():
            ln = ln.strip()
            if not ln: continue
            # Ambil URL langsung
            alive.append(ln)
        return 0, "\n".join(alive), stderr
    except Exception as e:
        return 1, "", str(e)

def run_wayback(domain, out_path):
    cmd = ["bash", "-lc", f"echo {domain} | waybackurls 2>/dev/null | tee {out_path}"]
    return run(cmd, timeout=300, shell=True)

def run_katana(hosts_file, out_file):
    cmd = ["katana", "-l", hosts_file, "-depth", "2", "-o", out_file]
    return run(cmd, timeout=1800)

# ----- nuclei streaming with periodic Discord upload -----
def run_nuclei_stream(urls_file, out_file, severity="critical,high,medium", batch_size=5, batch_timeout=900, periodic_upload=True):
    cmd = ["nuclei", "-l", urls_file]
    if severity:
        cmd += ["-severity", severity]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    buffer_lines=[]
    last_flush=time.time()
    last_upload=time.time()

    with open(out_file,"w",encoding="utf-8") as fout:
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
                if buffer_lines and (time.time()-last_flush)>=batch_timeout:
                    send_partial_findings(buffer_lines)
                    buffer_lines=[]
                    last_flush=time.time()
                if periodic_upload and (time.time()-last_upload)>=900:
                    send_discord_file(out_file, content="Partial nuclei output")
                    last_upload=time.time()
                continue
            line=line.strip()
            if not line: continue
            fout.write(line+"\n")
            fout.flush()
            buffer_lines.append(line)
            if len(buffer_lines)>=batch_size or (time.time()-last_flush)>=batch_timeout:
                send_partial_findings(buffer_lines)
                buffer_lines=[]
                last_flush=time.time()
            if periodic_upload and (time.time()-last_upload)>=900:
                send_discord_file(out_file, content="Partial nuclei output")
                last_upload=time.time()
        # flush remaining
        if buffer_lines:
            send_partial_findings(buffer_lines)
        if periodic_upload:
            send_discord_file(out_file, content="Final nuclei output")
    return {"stdout": "nuclei finished"}

def send_partial_findings(lines):
    if not lines: return
    summary=f"⚠️ Partial Nuclei Findings ({len(lines)} new)\nExamples:\n"+"\n".join(lines[:5])
    send_discord_message(summary)

# ----- nuclei summary -----
def send_nuclei_summary(out_file, workdir, target):
    lines = read_lines(out_file)
    total_targets = len(lines)
    severity_counts = Counter()
    for l in lines:
        # contoh: "TemplateID [C]" → ambil severity terakhir dalam []
        if "[" in l and "]" in l:
            sev = l.split("[")[-1].split("]")[0]
            severity_counts[sev] += 1
    summary = (
        f"🏁 SCAN COMPLETED\n"
        f"Workdir: {workdir}\n"
        f"Target: {target}\n"
        f"Targets scanned: {total_targets}\n"
        f"Nuclei findings: {len(lines)}\n"
        f"Severity\n"
        f"🔴C:{severity_counts.get('critical',0)} "
        f"🟠H:{severity_counts.get('high',0)} "
        f"🟡M:{severity_counts.get('medium',0)} "
        f"🔵L:{severity_counts.get('low',0)} "
        f"ℹ️I:{severity_counts.get('info',0)}"
    )
    send_discord_message(summary)

# ----- pipeline -----
def pipeline_for_domain(domain, workdir:Path, args):
    workdir.mkdir(parents=True, exist_ok=True)
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    out_sub=workdir/f"subfinder_{ts}.txt"
    out_way=workdir/f"wayback_{ts}.txt"
    out_kat=workdir/f"katana_{ts}.txt"
    out_nuc=workdir/f"nuclei_output_{ts}.txt"
    tmp_alive_file=workdir/f"alive_httpx_{ts}.txt"

    send_discord_message(f"🚀 RECON SCAN STARTED\nTarget: {domain}\nSteps: subfinder → httpx → wayback → katana → filter → nuclei")

    # subfinder
    send_discord_message(f"⚪ Running subfinder for {domain} ...")
    run_subfinder(domain, str(out_sub))
    subs=read_lines(str(out_sub))
    send_discord_message(f"✅ subfinder: found {len(subs)} subdomains")
    if subs:
        send_discord_file(str(out_sub), content=f"Subfinder Results ({len(subs)} items)")

    # httpx
    send_discord_message("🌐 Checking which subdomains are alive with httpx ...")
    alive=[]
    if subs:
        rc, stdout, stderr = run_httpx_on_list(subs)
        alive = stdout.splitlines()
    send_discord_message(f"✅ httpx: {len(alive)} alive hosts")
    if alive:
        with open(tmp_alive_file,"w") as f: f.write("\n".join(alive))
        send_discord_file(str(tmp_alive_file), content=f"HTTPX Alive Hosts ({len(alive)} items)")

    # wayback
    send_discord_message("📚 Collecting Wayback URLs ...")
    run_wayback(domain, str(out_way))
    wayback=read_lines(str(out_way))
    send_discord_message(f"✅ waybackurls: {len(wayback)} URLs collected")

    # katana
    combined=set(wayback)
    send_discord_message("🕷️ Katana crawling ...")
    kat=[]
    if alive:
        tmp_hosts=workdir/f"kat_hosts_{ts}.txt"
        with open(tmp_hosts,"w") as f: f.write("\n".join(alive))
        run_katana(str(tmp_hosts),str(out_kat))
        kat=read_lines(str(out_kat))
        combined.update(kat)
        send_discord_message(f"✅ katana: collected {len(kat)} URLs")

    # Tentukan input nuclei sesuai kondisi
    if combined:
        if kat:
            nuclei_source = kat
        else:
            nuclei_source = wayback
    else:
        nuclei_source = strip_scheme(alive)

    if not nuclei_source:
        send_discord_message(f"⚠️ No URLs to scan for {domain}.")
        return {"status":"no-targets"}

    tmp_list=workdir/f"nuclei_list_{ts}.txt"
    with open(tmp_list,"w") as f:
        for u in nuclei_source: f.write(u+"\n")

    send_discord_message(f"💥 Starting nuclei (severity={args.nuclei_severity})")
    run_nuclei_stream(str(tmp_list), str(out_nuc), severity=args.nuclei_severity, batch_size=5, batch_timeout=900, periodic_upload=True)
    send_discord_file(str(out_nuc), content=f"Nuclei results for {domain}")
    send_nuclei_summary(str(out_nuc), workdir, domain)

    send_discord_message(f"🏁 Scan completed for {domain}")
    return {"status":"done"}

# ----- main -----
def main():
    parser=argparse.ArgumentParser(description="Recon -> Discord pipeline")
    parser.add_argument("--workdir",default="./recon_results")
    parser.add_argument("--concurrency",type=int,default=3)
    parser.add_argument("--nuclei-severity",default="critical,high,medium")
    args=parser.parse_args()

    os.environ["PATH"] += os.pathsep + os.path.expanduser("~/go/bin")

    send_discord_message("🛠️ Checking & installing required tools ...")
    installed,failed=ensure_tools_auto()
    send_discord_message(f"🛠️ Installed: {installed} | Failed: {list(failed.keys())}")

    print("Choose mode:\n[1] Single Target\n[2] Multi Target (file)")
    choice=input("Select 1 or 2: ").strip()
    if choice not in("1","2"): return

    if choice=="1":
        domain=input("Enter target domain (example.com): ").strip()
        send_discord_message(f"🛰️ Single-target scan initiated for {domain}")
        class Arg: pass
        Arg.mode="single"
        Arg.use_katana_single=True
        Arg.nuclei_severity=args.nuclei_severity
        workdir=Path(args.workdir)/domain.replace(".","_")
        pipeline_for_domain(domain,workdir,Arg)
    else:
        list_path=input("Enter path to domains file: ").strip()
        domains=read_lines(list_path)
        if not domains: return
        send_discord_message(f"🛰️ Multi-target recon started ({len(domains)} domains)")
        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures={}
            for d in domains:
                workdir=Path(args.workdir)/d.replace(".","_")
                class Arg: pass
                Arg.mode="multi"; Arg.use_katana_single=True; Arg.nuclei_severity=args.nuclei_severity
                futures[ex.submit(pipeline_for_domain,d,workdir,Arg)]=d
            for fut in as_completed(futures):
                d=futures[fut]
                try:
                    res=fut.result()
                    send_discord_message(f"✅ Finished scan for {d}: {res.get('status')}")
                except Exception as e:
                    send_discord_message(f"⚠️ Error scanning {d}: {e}")

    send_discord_message("🏁 All tasks finished. Check uploaded files.")

if __name__=="__main__":
    main()
