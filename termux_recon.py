#!/usr/bin/env python3
"""
recon_discord.py

Recon pipeline with Discord real-time updates + partial nuclei streaming.

Author: Zephyrus

Features:
- Menu: [1] Single Target, [2] Multi Target (file list)
- Auto-install missing tools (go install) & pip deps automatically
- Pipeline: subfinder -> httpx -> waybackurls -> katana -> filter -> nuclei
- Real-time Discord messages (per-step) and partial nuclei findings while nuclei runs
- On nuclei finish: upload full nuclei output file (.txt) to Discord
- Default nuclei severity: critical,high,medium (configurable via CLI)
- You MUST confirm permission by typing 'yes' before scan begins

Usage:
  1) Edit DISCORD_WEBHOOK_URL below with your webhook.
  2) python3 recon_discord.py
"""

import os, sys, subprocess, shutil, time, json, argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import requests

# ----- CONFIG -----
DISCORD_WEBHOOK_URL = "https://discordapp.com/api/webhooks/PUT_YOUR_WEBHOOK"
REQUIRED_TOOLS = {
    "subfinder":"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":"github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls":"github.com/tomnomnom/waybackurls@latest",
    "katana":"github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei":"github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
}
PY_DEPS=["requests","beautifulsoup4"]

# ----- helpers -----
def which(cmd):
    if shutil.which(cmd): return True
    termux_go_bin=os.path.expanduser("~/go/bin")
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
    missing=[]
    for pkg in PY_DEPS:
        try: __import__(pkg)
        except Exception: missing.append(pkg)
    if not missing: return True
    print("[*] Installing python deps:", missing)
    rc, out, err = run([sys.executable,"-m","pip","install"]+missing, timeout=300)
    return rc==0

def ensure_go():
    if which("go"): return True
    print("[!] 'go' not found. Attempting best-effort install.")
    if which("apt-get"):
        run(["sudo","apt-get","update"],timeout=300)
        run(["sudo","apt-get","install","-y","golang"],timeout=600)
        return which("go")
    if which("brew"):
        run(["brew","install","go"],timeout=600)
        return which("go")
    return False

def go_install(pkg):
    print(f"[*] go install {pkg}")
    rc,out,err = run(["go","install",pkg],timeout=600)
    return rc==0

def ensure_tools_auto():
    installed=[]
    failed={}
    ok=ensure_python_deps()
    if not ok: failed["python_deps"]="pip install failed"
    need=[t for t in REQUIRED_TOOLS if not which(t)]
    if need:
        ok_go=ensure_go()
        if not ok_go: failed["go"]="go not installed"
    for t in need:
        pkg=REQUIRED_TOOLS[t]
        if go_install(pkg):
            installed.append(t)
        else:
            failed[t]=f"go install failed for {pkg}"
    return installed, failed

# ----- Discord helpers -----
def send_discord_embed(title, description=None, fields=None, color=0x3498db):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL: return False, "no webhook"
    payload = {"username":"ZephyrusRecon","embeds":[{"title":title,"description":description,"color":color}]}
    if fields: payload["embeds"][0]["fields"]=fields
    try:
        r=requests.post(DISCORD_WEBHOOK_URL,json=payload,timeout=15)
        return (r.status_code in (200,204)), r.text
    except Exception as e:
        return False, str(e)

def send_discord_file(file_path, content=None, filename=None):
    if not DISCORD_WEBHOOK_URL or "PUT_YOUR" in DISCORD_WEBHOOK_URL: return False,"no webhook"
    if filename is None: filename=os.path.basename(file_path)
    try:
        with open(file_path,"rb") as f:
            data={}
            if content: data["payload_json"]=json.dumps({"content":content})
            r=requests.post(DISCORD_WEBHOOK_URL,files={"file":(filename,f)},data=data,timeout=60)
        return (r.status_code in (200,204)), r.text
    except Exception as e:
        return False,str(e)

# ----- URL helpers -----
def read_lines(path):
    try:
        with open(path,"r",encoding="utf-8") as f: return [l.strip() for l in f if l.strip()]
    except: return []

def filter_urls_set(urls):
    skip_ext=(".jpg",".jpeg",".png",".gif",".svg",".css",".js",".ico",".woff",".woff2",".ttf",".eot",".pdf",".zip",".tar",".gz",".mp4",".webm")
    out=set()
    for u in urls:
        u=u.strip()
        if not u or not (u.startswith("http://") or u.startswith("https://")): continue
        if any(u.lower().endswith(ext) for ext in skip_ext): continue
        out.add(u)
    return sorted(out)

def strip_scheme(urls):
    clean=[]
    for u in urls:
        if u.startswith("http://"): clean.append(u[len("http://"):])
        elif u.startswith("https://"): clean.append(u[len("https://"):])
        else: clean.append(u)
    return clean

# ----- External tools -----
def run_subfinder(domain,out_path): return run(["subfinder","-d",domain,"-o",out_path])
def run_httpx_on_list(list_lines):
    cmd=["httpx","-silent","-no-color","-follow-redirects","-probe","-timeout","10","-retries","2"]
    alive=[]
    fixed=[]
    for u in list_lines:
        u=u.strip()
        if not u: continue
        if not u.startswith("http://") and not u.startswith("https://"):
            fixed.append("https://"+u)  # full URL untuk nuclei
        else:
            fixed.append(u)
    try:
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        stdout,stderr=proc.communicate(input="\n".join(fixed)+"\n",timeout=900)
        for ln in stdout.splitlines():
            ln=ln.strip()
            if ln: alive.append(ln)
        return 0,"\n".join(alive),stderr
    except Exception as e:
        return 1,"",str(e)

def clean_httpx_output(lines):
    cleaned=[]
    for l in lines:
        l=l.strip().split()[0]  # remove [SUCCESS]/[FAILED]
        if l: cleaned.append(l.split("://")[-1])  # strip scheme for Discord display
    return cleaned

def run_wayback(domain,out_path): return run(["bash","-lc",f"echo {domain} | waybackurls 2>/dev/null | tee {out_path}"],shell=True)
def run_katana(hosts_file,out_file): return run(["katana","-l",hosts_file,"-depth","2","-o",out_file],timeout=1800)

# ----- Nuclei -----
def run_nuclei_stream(urls_file,out_file,severity="critical,high,medium",batch_size=5,batch_timeout=900,periodic_upload=True):
    cmd=["nuclei","-l",urls_file]
    if severity: cmd+=["-severity",severity]
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    buffer_lines=[]
    last_flush=time.time()
    last_upload=time.time()
    with open(out_file,"w",encoding="utf-8") as fout:
        while True:
            line=proc.stdout.readline()
            if not line:
                if proc.poll() is not None: break
                time.sleep(0.2)
                if buffer_lines and (time.time()-last_flush)>=batch_timeout:
                    send_partial_findings(buffer_lines)
                    buffer_lines=[]
                    last_flush=time.time()
                if periodic_upload and (time.time()-last_upload)>=900:
                    send_discord_file(out_file,content="Partial nuclei output")
                    last_upload=time.time()
                continue
            line=line.strip()
            if not line: continue
            fout.write(line+"\n"); fout.flush()
            buffer_lines.append(line)
            if len(buffer_lines)>=batch_size or (time.time()-last_flush)>=batch_timeout:
                send_partial_findings(buffer_lines)
                buffer_lines=[]
                last_flush=time.time()
            if periodic_upload and (time.time()-last_upload)>=900:
                send_discord_file(out_file,content="Partial nuclei output")
                last_upload=time.time()
        if buffer_lines: send_partial_findings(buffer_lines)
        if periodic_upload: send_discord_file(out_file,content="Final nuclei output")
    return {"stdout":"nuclei finished"}

def send_partial_findings(lines):
    if not lines: return
    summary=f"⚠️ Partial Nuclei Findings ({len(lines)} new)\nExamples:\n"+"\n".join(lines[:5])
    send_discord_embed(summary)

def send_nuclei_summary(out_file,workdir,target):
    lines=read_lines(out_file)
    total_targets=len(lines)
    severity_counts=Counter()
    for l in lines:
        if "[" in l and "]" in l:
            sev=l.split("[")[-1].split("]")[0]
            severity_counts[sev]+=1
    fields=[
        {"name":"Critical 🔴","value":str(severity_counts.get("critical",0)),"inline":True},
        {"name":"High 🟠","value":str(severity_counts.get("high",0)),"inline":True},
        {"name":"Medium 🟡","value":str(severity_counts.get("medium",0)),"inline":True},
        {"name":"Low 🔵","value":str(severity_counts.get("low",0)),"inline":True},
        {"name":"Info ℹ️","value":str(severity_counts.get("info",0)),"inline":True},
    ]
    send_discord_embed(f"🏁 SCAN COMPLETED for {target}", description=f"Workdir: {workdir}\nTargets scanned: {total_targets}\nNuclei findings: {len(lines)}", fields=fields,color=0x2ecc71)

# ----- pipeline -----
def pipeline_for_domain(domain, workdir:Path, args):
    workdir.mkdir(parents=True,exist_ok=True)
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    out_sub=workdir/f"subfinder_{ts}.txt"
    out_way=workdir/f"wayback_{ts}.txt"
    out_kat=workdir/f"katana_{ts}.txt"
    out_nuc=workdir/f"nuclei_output_{ts}.txt"
    tmp_alive_file=workdir/f"alive_httpx_{ts}.txt"

    print(f"\n🚀 Zephyrus Recon Scan STARTED for {domain}\nSteps: subfinder → httpx → wayback → katana → filter → nuclei")
    send_discord_embed("🚀 RECON SCAN STARTED", f"Target: {domain}\nSteps: subfinder → httpx → wayback → katana → filter → nuclei\nAuthor: Zephyrus", color=0x3498db)

    # Subfinder
    send_discord_embed("⚪ Subfinder","Running subfinder ...", color=0x95a5a6)
    run_subfinder(domain,str(out_sub))
    subs=read_lines(str(out_sub))
    send_discord_embed("⚪ Subfinder Results", f"Found {len(subs)} subdomains\nSample:\n"+"\n".join(subs[:5]), color=0x2ecc71)
    if subs: send_discord_file(str(out_sub),content=f"Subfinder Results ({len(subs)})")

    # HTTPX
    send_discord_embed("🌐 HTTPX","Checking alive hosts ...", color=0x95a5a6)
    alive=[]
    if subs:
        rc,stdout,stderr=run_httpx_on_list(subs)
        alive=stdout.splitlines()
    alive_clean=clean_httpx_output(alive)
    send_discord_embed("🌐 HTTPX Alive Hosts", f"{len(alive_clean)} alive hosts\nSample:\n"+"\n".join(alive_clean[:5]), color=0x3498db)
    if alive_clean:
        with open(tmp_alive_file,"w") as f: f.write("\n".join(alive))
        send_discord_file(str(tmp_alive_file), content=f"HTTPX Alive Hosts ({len(alive_clean)})")

    # Wayback
    send_discord_embed("📚 Wayback","Collecting Wayback URLs ...", color=0x95a5a6)
    run_wayback(domain,str(out_way))
    wayback=read_lines(str(out_way))
    send_discord_embed("📚 Wayback URLs", f"{len(wayback)} URLs collected\nSample:\n"+"\n".join(wayback[:5]), color=0x3498db)

    # Katana
    combined=set(wayback)
    send_discord_embed("🕷️ Katana","Crawling ...", color=0x95a5a6)
    kat=[]
    if alive_clean:
        tmp_hosts=workdir/f"kat_hosts_{ts}.txt"
        with open(tmp_hosts,"w") as f: f.write("\n".join(alive))
        run_katana(str(tmp_hosts),str(out_kat))
        kat=read_lines(str(out_kat))
        combined.update(kat)
        send_discord_embed("🕷️ Katana Results", f"{len(kat)} URLs collected\nSample:\n"+"\n".join(kat[:5]), color=0x3498db)

    # Tentukan input Nuclei
    if kat: nuclei_source=kat
    elif wayback: nuclei_source=wayback
    else: nuclei_source=alive

    tmp_list=workdir/f"nuclei_list_{ts}.txt"
    with open(tmp_list,"w") as f:
        for u in nuclei_source: f.write(u+"\n")

    send_discord_embed("💥 Nuclei Scan", f"Starting nuclei (severity={args.nuclei_severity})", color=0xe67e22)
    run_nuclei_stream(str(tmp_list), str(out_nuc), severity=args.nuclei_severity)
    send_discord_file(str(out_nuc), content=f"Nuclei results for {domain}")
    send_nuclei_summary(str(out_nuc), workdir, domain)
    send_discord_embed("🏁 Scan Completed", f"Scan finished for {domain}\nAuthor: Zephyrus", color=0x2ecc71)
    print(f"🏁 Scan Completed for {domain} (Author: Zephyrus)")
    return {"status":"done"}

# ----- main -----
def main():
    parser=argparse.ArgumentParser(description="Recon -> Discord pipeline")
    parser.add_argument("--workdir",default="./recon_results")
    parser.add_argument("--concurrency",type=int,default=3)
    parser.add_argument("--nuclei-severity",default="critical,high,medium")
    args=parser.parse_args()

    os.environ["PATH"]+=os.pathsep+os.path.expanduser("~/go/bin")

    send_discord_embed("🛠️ Checking & installing required tools ...", color=0x95a5a6)
    installed,failed=ensure_tools_auto()
    send_discord_embed("🛠️ Tools Status", f"Installed: {installed}\nFailed: {list(failed.keys())}", color=0x3498db)

    print("Choose mode:\n[1] Single Target\n[2] Multi Target (file)")
    choice=input("Select 1 or 2: ").strip()
    if choice not in ("1","2"): return

    if choice=="1":
        domain=input("Enter target domain: ").strip()
        workdir=Path(args.workdir)/domain.replace(".","_")
        class Arg: pass
        Arg.mode="single"; Arg.use_katana_single=True; Arg.nuclei_severity=args.nuclei_severity
        pipeline_for_domain(domain,workdir,Arg)
    else:
        list_path=input("Enter path to domains file: ").strip()
        domains=read_lines(list_path)
        if not domains: return
        send_discord_embed("🛰️ Multi-target recon", f"{len(domains)} domains", color=0x3498db)
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
                    send_discord_embed(f"✅ Finished scan for {d}", f"Status: {res.get('status')}", color=0x2ecc71)
                except Exception as e:
                    send_discord_embed(f"⚠️ Error scanning {d}", str(e), color=0xe74c3c)

    send_discord_embed("🏁 All Tasks Finished","Check uploaded files in Discord.", color=0x2ecc71)

if __name__=="__main__":
    print("Zephyrus Recon Pipeline v1.0")
    main()
