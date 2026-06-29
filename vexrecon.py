#!/usr/bin/env python3
"""
vexRecon WIDE - Domain Reconnaissance Tool
For authorized penetration testing and bug bounty programs only.
"""

import subprocess, sys, os, re, json, shutil, threading, ipaddress, requests
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()

# ─────────────────────────────────────────────────────────────
BANNER = r"""
____    ____  __________   ___ .______       _______   ______   ______   .__   __. 
\   \  /   / |   ____\  \ /  / |   _  \     |   ____| /      | /  __  \  |  \ |  | 
 \   \/   /  |  |__   \  V  /  |  |_)  |    |  |__   |  ,----'|  |  |  | |   \|  | 
  \      /   |   __|   >   <   |      /     |   __|  |  |     |  |  |  | |  . `  | 
   \    /    |  |____ /  .  \  |  |\  \----.|  |____ |  `----.|  `--'  | |  |\   | 
    \__/     |_______/__/ \__\ | _| `._____||_______| \______| \______/  |__| \__| 
                                                                                   

                              [ vexRecon WIDE ]
                     Domain Reconnaissance & OSINT Framework
"""

# ─────────────────────────────────────────────────────────────
REQUIRED_TOOLS = {
    "dig":        "https://linux.die.net/man/1/dig              apt install dnsutils",
    "dnsx":       "https://github.com/projectdiscovery/dnsx     go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "subfinder":  "https://github.com/projectdiscovery/subfinder  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "shuffledns": "https://github.com/projectdiscovery/shuffledns  go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    "httpx":      "https://github.com/projectdiscovery/httpx    go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "ffuf":       "https://github.com/ffuf/ffuf                 go install github.com/ffuf/ffuf/v2@latest",
    "naabu":      "https://github.com/projectdiscovery/naabu    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "wget":       "https://www.gnu.org/software/wget/           apt install wget",
}

FILTERED_PREFIXES = ["10.10.34.", "10.10."]

CDN_RANGES = {
    "Cloudflare":        ["103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
                          "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
                          "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
                          "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"],
    "Akamai":            ["23.32.0.0/11","23.64.0.0/14","104.64.0.0/10","184.24.0.0/13"],
    "Fastly":            ["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
                          "151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","185.31.16.0/22",
                          "199.27.72.0/21","199.232.0.0/16"],
    "Amazon CloudFront": ["13.32.0.0/15","13.35.0.0/16","52.84.0.0/15","54.182.0.0/16",
                          "54.192.0.0/16","54.230.0.0/16","64.252.64.0/18","99.84.0.0/16",
                          "204.246.164.0/22","205.251.192.0/19","216.137.32.0/19"],
}

WORDLISTS = {
    "5k":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "20k":    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "110k":   "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
    "4char":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/four-character-subdomains.txt",
}
RESOLVERS_URL = "https://raw.githubusercontent.com/TheWation/PassGate/master/dns/trusted_resolvers.txt"

BUILTIN_WL = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","dns","ns1","ns2","ns3",
    "mx","mx1","mx2","api","dev","stage","staging","test","demo","beta","alpha","uat",
    "prod","production","app","apps","admin","panel","dashboard","portal","login","auth",
    "sso","oauth","accounts","account","secure","ssl","cdn","static","assets","media",
    "img","images","video","files","upload","downloads","docs","help","support","status",
    "health","monitor","metrics","grafana","kibana","jenkins","gitlab","git","svn","jira",
    "confluence","wiki","blog","shop","store","pay","payment","checkout","cart","invoice",
    "billing","crm","erp","hr","internal","intranet","extranet","remote","vpn2","gateway",
    "proxy","firewall","router","switch","backup","archive","old","new","web","web1","web2",
    "server","server1","server2","host","hosting","cloud","k8s","kubernetes","docker",
    "registry","ci","cd","deploy","build","test1","test2","sandbox","preview","review",
    "m","mobile","wap","pwa","ws","chat","meet","calendar","email","webmail","mail2",
    "relay","lists","newsletter","news","forum","community","jobs","careers","about",
    "contact","info","data","db","database","redis","mongo","elastic","search","s3",
    "storage","backup2","dr","failover","ha","lb","a","b","c","d","e","f","g","h",
    "i","j","k","l","n","o","p","q","r","s","t","u","v","x","y","z",
    "1","2","3","4","5","10","100","2024","2025",
]

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def check_tools():
    return [(t, l) for t, l in REQUIRED_TOOLS.items() if not shutil.which(t)]

def is_filtered(ip):
    return any(ip.startswith(p) for p in FILTERED_PREFIXES)

def cdn_check(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for name, ranges in CDN_RANGES.items():
            for cidr in ranges:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True, name
    except Exception:
        pass
    return False, ""

def run_cmd(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"not found: {cmd[0]}", -1

def find_ips(text):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def wfile(path, lines):
    Path(path).write_text("\n".join(str(l) for l in lines) + "\n", encoding="utf-8")

def afile(path, line):
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def logmsg(log, msg):
    with open(log, "a") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

def ip_folder(ips_dir, ip):
    d = ips_dir / ip
    d.mkdir(exist_ok=True)
    return d

def download(url, dest, timeout=120):
    _, _, rc = run_cmd(["wget", "-q", "--timeout=30", url, "-O", str(dest)], timeout=timeout)
    if rc == 0 and Path(dest).exists() and Path(dest).stat().st_size > 100:
        return True
    _, _, rc2 = run_cmd(["curl", "-sL", "--max-time", "30", url, "-o", str(dest)], timeout=timeout)
    return rc2 == 0 and Path(dest).exists() and Path(dest).stat().st_size > 100

# ─────────────────────────────────────────────────────────────
# OSINT
# ─────────────────────────────────────────────────────────────

def osint_informer(domain):
    out = {}
    try:
        r = requests.get(f"https://website.informer.com/{domain}", headers={"User-Agent": UA}, timeout=15)
        ips = find_ips(r.text)
        if ips:
            out["ips"] = list(set(ips))
        m = re.search(r'<title>(.*?)</title>', r.text, re.I)
        if m:
            out["title"] = m.group(1).strip()
    except Exception as e:
        out["error"] = str(e)
    return out

def osint_whoxy(domain):
    out = {}
    try:
        r = requests.get(f"https://www.whoxy.com/{domain}#history", headers={"User-Agent": UA}, timeout=15)
        emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r.text)
        if emails:
            out["emails"] = list(set(emails))
        m = re.search(r'Registrar[:\s]+([^\n<]{3,80})', r.text, re.I)
        if m:
            out["registrar"] = m.group(1).strip()
        m = re.search(r'Creation Date[:\s]+([^\n<]{3,30})', r.text, re.I)
        if m:
            out["created"] = m.group(1).strip()
    except Exception as e:
        out["error"] = str(e)
    return out

# ─────────────────────────────────────────────────────────────
# CORE RECON
# ─────────────────────────────────────────────────────────────

def run_recon(domain, tlds_file, outdir, wl_path, progress, task):
    ips_dir = outdir / "ips"
    ips_dir.mkdir(exist_ok=True)
    log = outdir / "log.txt"

    d = {
        "domain": domain,
        # dns
        "ns": [], "a": [], "mx": [], "mx_a": [], "txt": [],
        # ips
        "ips": [], "cdn": {}, "non_cdn": [],
        "spf_warn": False,
        # subdomains
        "subs": [], "active": {},
        # results
        "http": {},          # host -> {status, title, ip, cdn, tech}
        "tld_hits": [],
        "ptr": {},           # ip -> [ptrs]
        "ssl": {},           # ip -> [lines]
        "vhosts": {},        # ip -> [hosts]
        "ports": {},         # ip -> [ports]
        "takeover": [],
        # osint
        "informer": {},
        "whoxy": {},
    }

    STEPS = 18
    n = [0]

    def step(msg):
        n[0] += 1
        progress.update(task, completed=int(n[0]/STEPS*100), description=f"[cyan]{msg}")
        logmsg(log, msg)

    def add_ip(ip):
        if is_filtered(ip) or not valid_ip(ip):
            return
        if ip not in d["ips"]:
            d["ips"].append(ip)
        is_cdn, cdn_name = cdn_check(ip)
        if is_cdn:
            d["cdn"].setdefault(ip, cdn_name)
        elif ip not in d["non_cdn"]:
            d["non_cdn"].append(ip)

    # 1. OSINT
    step("OSINT — website.informer")
    d["informer"] = osint_informer(domain)

    step("OSINT — whoxy WHOIS")
    d["whoxy"] = osint_whoxy(domain)

    # 3. TLD fuzz
    step("TLD fuzzing")
    if os.path.isfile(tlds_file):
        tmp = outdir / "_tld.txt"
        run_cmd(["dnsx", "-d", f"{domain}FUZZ", "-w", tlds_file, "-silent", "-o", str(tmp)], timeout=120)
        if tmp.exists():
            d["tld_hits"] = [l.strip() for l in tmp.read_text().splitlines() if l.strip()]
            tmp.unlink()
    else:
        logmsg(log, f"[WARN] tlds.txt not found: {tlds_file}")

    # 4. DNS
    step("DNS records")

    out, _, _ = run_cmd(["dig", "+short", "ns", domain])
    d["ns"] = [l.strip() for l in out.splitlines() if l.strip()]

    out, _, _ = run_cmd(["dig", "+short", "a", domain])
    d["a"] = [l.strip() for l in out.splitlines() if valid_ip(l.strip())]
    for ip in d["a"]:
        add_ip(ip)

    out, _, _ = run_cmd(["dig", "+short", "mx", domain])
    d["mx"] = [l.strip() for l in out.splitlines() if l.strip()]
    for line in d["mx"]:
        parts = line.split()
        host  = parts[-1].rstrip(".") if parts else ""
        if host:
            out2, _, _ = run_cmd(["dig", "+short", "a", host])
            for ip in [x.strip() for x in out2.splitlines() if valid_ip(x.strip())]:
                d["mx_a"].append(ip)
                add_ip(ip)

    out, _, _ = run_cmd(["dig", "+short", "txt", domain])
    d["txt"] = [l.strip() for l in out.splitlines() if l.strip()]
    for txt in d["txt"]:
        for ip in find_ips(txt):
            add_ip(ip)
        if "v=spf1" in txt.lower() and "-all" not in txt.lower():
            d["spf_warn"] = True

    # 5. subfinder
    step("subfinder")
    tmp_sf = outdir / "_sf.txt"
    run_cmd(["subfinder", "-all", "-d", domain, "-silent", "-o", str(tmp_sf)], timeout=600)
    sf = [l.strip() for l in tmp_sf.read_text().splitlines() if l.strip()] if tmp_sf.exists() else []
    if tmp_sf.exists(): tmp_sf.unlink()

    # 6. resolvers
    step("Downloading resolvers")
    tmp_res = outdir / "_res.txt"
    if not download(RESOLVERS_URL, tmp_res):
        logmsg(log, "[WARN] Could not download resolvers")

    # 7. shuffledns
    step("shuffledns bruteforce")
    tmp_sh = outdir / "_sh.txt"
    if wl_path and os.path.isfile(wl_path) and tmp_res.exists():
        run_cmd(["shuffledns", "-d", domain, "-w", wl_path, "-r", str(tmp_res),
                 "-mode", "bruteforce", "-o", str(tmp_sh), "-silent"], timeout=900)
    sh = [l.strip() for l in tmp_sh.read_text().splitlines() if l.strip()] if tmp_sh.exists() else []
    if tmp_sh.exists(): tmp_sh.unlink()
    if tmp_res.exists(): tmp_res.unlink()

    d["subs"] = sorted(set(sf + sh))
    subs_file = outdir / "_subs.txt"
    wfile(subs_file, d["subs"])

    # 8. dnsx resolve
    step("dnsx — resolving subdomains")
    if subs_file.exists() and d["subs"]:
        out, _, _ = run_cmd(["dnsx", "-l", str(subs_file), "-a", "-resp", "-json", "-silent"], timeout=600)
        for line in out.splitlines():
            try:
                rec  = json.loads(line)
                host = rec.get("host", "")
                ips  = [ip for ip in rec.get("a", []) if not is_filtered(ip) and valid_ip(ip)]
                if ips:
                    d["active"][host] = ips
                    for ip in ips:
                        add_ip(ip)
            except Exception:
                pass

    # 9. httpx
    step("httpx — HTTP probing")
    if subs_file.exists() and d["subs"]:
        out, _, _ = run_cmd([
            "httpx", "-l", str(subs_file),
            "-title", "-cdn", "-ip", "-status-code", "-tech-detect",
            "-follow-host-redirects", "-silent",
            "-H", f"User-Agent: {UA}",
            "-H", f"Referer: https://{domain}/",
            "-threads", "1", "-json",
        ], timeout=600)
        for line in out.splitlines():
            try:
                rec  = json.loads(line)
                host = rec.get("input", "")
                sc   = rec.get("status_code")
                d["http"][host] = {
                    "status": sc,
                    "title":  rec.get("title", ""),
                    "ip":     rec.get("host", ""),
                    "cdn":    rec.get("cdn", False),
                    "tech":   ", ".join(rec.get("technologies", [])),
                }
                if sc in [404, 403] and not rec.get("cdn"):
                    d["takeover"].append(host)
            except Exception:
                pass

    # 10. Reverse DNS → per-IP ptr.txt
    step("Reverse DNS (PTR)")
    for ip in list(set(d["ips"])):
        out, _, _ = run_cmd(["dig", "+short", "-x", ip], timeout=10)
        ptrs = [l.strip() for l in out.splitlines() if l.strip()]
        if ptrs:
            d["ptr"][ip] = ptrs
            wfile(ip_folder(ips_dir, ip) / "ptr.txt", ptrs)

    # 11. SSL probe → per-IP ssl.txt
    step("SSL/TLS probing")
    tmp_nc = outdir / "_nc.txt"
    wfile(tmp_nc, d["non_cdn"])
    if d["non_cdn"]:
        out, _, _ = run_cmd(["httpx", "-l", str(tmp_nc), "-tls-probe", "-silent", "-json"], timeout=300)
        for line in out.splitlines():
            try:
                rec  = json.loads(line)
                ip   = rec.get("input", "").split(":")[0]
                tls  = rec.get("tls", {})
                cn   = tls.get("subject_cn", "")
                sans = tls.get("subject_an", [])
                if cn or sans:
                    info = ([f"CN: {cn}"] if cn else []) + [f"SAN: {s}" for s in sans]
                    d["ssl"][ip] = info
                    wfile(ip_folder(ips_dir, ip) / "ssl.txt", info)
            except Exception:
                pass
    if tmp_nc.exists(): tmp_nc.unlink()

    # 12. Virtual hosts → per-IP vhosts.txt
    step("Virtual host discovery (ffuf)")
    tmp_nc2  = outdir / "_nc2.txt"
    tmp_vh   = outdir / "_vh.json"
    wfile(tmp_nc2, d["non_cdn"])
    if d["non_cdn"] and d["subs"]:
        run_cmd([
            "ffuf",
            "-w", f"{tmp_nc2}:IP,{subs_file}:HOST",
            "-u", "http://IP/",
            "-H", "Host: HOST",
            "-mr", "HOST",
            "-H", f"User-Agent: {UA}",
            "-H", "Referer: http://HOST/",
            "-o", str(tmp_vh), "-of", "json", "-silent",
        ], timeout=600)
        if tmp_vh.exists():
            try:
                for r_ in json.loads(tmp_vh.read_text()).get("results", []):
                    ip_   = r_.get("input", {}).get("IP", "")
                    host_ = r_.get("input", {}).get("HOST", "")
                    sc_   = r_.get("status", 0)
                    d["vhosts"].setdefault(ip_, []).append(f"{host_} [{sc_}]")
                    afile(ip_folder(ips_dir, ip_) / "vhosts.txt", f"{host_} [{sc_}]")
            except Exception:
                pass
            tmp_vh.unlink()
    if tmp_nc2.exists(): tmp_nc2.unlink()

    # 13. cleanup temp subs file
    if subs_file.exists(): subs_file.unlink()

    # 14-15: placeholders for port scan (done after recon in main)
    step("Building resource links")
    step("Writing output files")

    # Write final results.txt
    write_results(domain, d, outdir)
    return d


# ─────────────────────────────────────────────────────────────
# PORT SCAN → per-IP ports.txt
# ─────────────────────────────────────────────────────────────

def run_portscan(outdir, d):
    ips_dir = outdir / "ips"
    if not d["ips"]:
        return
    tmp = outdir / "_ps.txt"
    wfile(tmp, d["ips"])
    out_file = outdir / "_ps_out.txt"
    run_cmd(["naabu", "-list", str(tmp), "-silent", "-top-ports", "1000", "-o", str(out_file)], timeout=900)
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if ":" in line:
                ip_, port = line.rsplit(":", 1)
                d["ports"].setdefault(ip_, []).append(port)
                afile(ip_folder(ips_dir, ip_) / "ports.txt", port)
        out_file.unlink()
    if tmp.exists(): tmp.unlink()


# ─────────────────────────────────────────────────────────────
# FINAL results.txt
# ─────────────────────────────────────────────────────────────

def write_results(domain, d, outdir):
    lines = []
    div   = "─" * 60

    def section(title):
        lines.extend(["", div, f"  {title}", div])

    lines.append(BANNER.strip())
    lines.append(f"\n  Target : {domain}")
    lines.append(f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── OSINT ────────────────────────────────────────────────
    section("OSINT")
    inf = d["informer"]
    if inf.get("title"):    lines.append(f"  Title      : {inf['title']}")
    if inf.get("ips"):      lines.append(f"  IPs seen   : {', '.join(inf['ips'])}")
    wx = d["whoxy"]
    if wx.get("emails"):    lines.append(f"  Emails     : {', '.join(wx['emails'])}")
    if wx.get("registrar"): lines.append(f"  Registrar  : {wx['registrar']}")
    if wx.get("created"):   lines.append(f"  Created    : {wx['created']}")

    # ── DNS ──────────────────────────────────────────────────
    section("DNS")
    lines.append(f"  NS  : {', '.join(d['ns']) or '-'}")
    lines.append(f"  A   : {', '.join(d['a']) or '-'}")
    if d["mx"]:
        lines.append(f"  MX  :")
        for r in d["mx"]: lines.append(f"        {r}")
    if d["txt"]:
        lines.append(f"  TXT :")
        for r in d["txt"]: lines.append(f"        {r}")

    # ── SPF ──────────────────────────────────────────────────
    if d["spf_warn"]:
        section("SPF WARNING")
        lines.append(f"  No -all in SPF record — email spoofing may be possible for @{domain}")
        lines.append(f"  Attackers could send phishing emails pretending to be from this domain.")

    # ── TLD Hits ─────────────────────────────────────────────
    if d["tld_hits"]:
        section("TLD Fuzzing Hits")
        for t in d["tld_hits"]:
            lines.append(f"  {t}")

    # ── Subdomains by status code ─────────────────────────────
    by_status: dict = {}
    for host, info in d["http"].items():
        sc = info.get("status") or 0
        by_status.setdefault(sc, []).append(host)

    for sc in [200, 301, 302, 403, 404]:
        hosts = sorted(by_status.get(sc, []))
        if not hosts:
            continue
        section(f"[{sc}] Subdomains")
        for h in hosts:
            info    = d["http"][h]
            cdn_tag = "  [CDN]" if info.get("cdn") else ""
            tech    = f"  [{info['tech']}]" if info.get("tech") else ""
            title   = f"  {info['title']}" if info.get("title") else ""
            lines.append(f"  {h}{cdn_tag}{tech}{title}")

    # catch-all for other status codes (5xx, etc.)
    other_sc = [sc for sc in sorted(by_status.keys()) if sc not in [200, 301, 302, 403, 404]]
    for sc in other_sc:
        hosts = sorted(by_status[sc])
        section(f"[{sc}] Subdomains")
        for h in hosts:
            info    = d["http"][h]
            cdn_tag = "  [CDN]" if info.get("cdn") else ""
            lines.append(f"  {h}{cdn_tag}")

    # DNS-only subdomains (no HTTP response)
    no_http = sorted(set(d["subs"]) - set(d["http"].keys()))
    if no_http:
        section("[DNS only] Subdomains")
        for h in no_http:
            ips_ = d["active"].get(h, [])
            lines.append(f"  {h}  →  {', '.join(ips_)}" if ips_ else f"  {h}")

    # ── Subdomain Takeover ───────────────────────────────────
    if d["takeover"]:
        section("Subdomain Takeover Candidates")
        for s in sorted(d["takeover"]):
            lines.append(f"  {s}")

    # ── CDN IPs ──────────────────────────────────────────────
    if d["cdn"]:
        section("CDN IPs")
        for ip, name in d["cdn"].items():
            lines.append(f"  {ip}  [{name}]")
        lines.append("")
        lines.append("  To find the real IP behind CDN:")
        lines.append("  1. Check email headers received from the site")
        lines.append("  2. Search favicon hash on Shodan")
        lines.append(f"  3. https://www.shodan.io/search?query=ssl.cert.subject.cn%3A{domain}")
        lines.append(f"  4. https://search.censys.io/search?resource=hosts&q={domain}")
        lines.append(f"  5. https://leakix.net/search?scope=service&q={domain}")
        lines.append(f"  6. https://en.fofa.info/result?qbase64={domain}")
        lines.append(f"  7. https://www.zoomeye.hk/searchResult?q=site%3A%22{domain}%22")

    # ── IPs ──────────────────────────────────────────────────
    section("IPs")
    for ip in sorted(d["ips"], key=lambda x: [int(p) for p in x.split(".")]):
        parts = [ip]
        if ip in d["cdn"]:
            parts.append(f"[{d['cdn'][ip]}]")
        if ip in d["ptr"]:
            parts.append(f"PTR={', '.join(d['ptr'][ip])}")
        if ip in d["ssl"]:
            cn = next((l.replace("CN: ","") for l in d["ssl"][ip] if l.startswith("CN:")), "")
            if cn: parts.append(f"SSL={cn}")
        if ip in d["ports"]:
            parts.append(f"ports={','.join(d['ports'][ip])}")
        lines.append("  " + "  ".join(parts))

    # ── IP Recon Links ───────────────────────────────────────
    non_cdn_ips = d["non_cdn"]
    if non_cdn_ips:
        section("IP Recon Links")
        for ip in non_cdn_ips:
            lines.append(f"\n  [ {ip} ]")
            lines.append(f"    https://search.dnslytics.com/search?d=domains&q={ip}")
            lines.append(f"    https://www.bing.com/search?q=ip%3A+{ip}")
            lines.append(f"    https://www.virustotal.com/gui/ip-address/{ip}/relations")
            lines.append(f"    https://reverseip.domaintools.com/search/?q={ip}")
            lines.append(f"    https://hackertarget.com/reverse-ip-lookup/")
            lines.append(f"    https://www.yougetsignal.com/tools/web-sites-on-web-server/")

    # ── Virtual Hosts ────────────────────────────────────────
    if d["vhosts"]:
        section("Virtual Hosts")
        for ip, hosts in d["vhosts"].items():
            lines.append(f"\n  [ {ip} ]")
            for h in hosts:
                lines.append(f"    {h}")

    (outdir / "results.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    console.print("[bold yellow]Checking required tools...[/bold yellow]\n")
    missing = check_tools()
    if missing:
        console.print("[bold red]✗ Missing tools:[/bold red]\n")
        for tool, link in missing:
            console.print(f"  [red]• {tool}[/red]")
            console.print(f"    [dim]{link}[/dim]\n")
        console.print("[bold red]Install the missing tools above, then re-run.[/bold red]")
        sys.exit(1)
    console.print("[bold green]✓ All tools present.[/bold green]\n")

    domain    = Prompt.ask("[bold cyan]Target domain[/bold cyan]", default="example.com")
    domain    = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    tlds_file = Prompt.ask("[cyan]Path to tlds.txt[/cyan]", default="tlds.txt")

    console.print("\n[bold cyan]Wordlist for shuffledns:[/bold cyan]")
    console.print("  [1] 5k")
    console.print("  [2] 20k")
    console.print("  [3] 110k")
    console.print("  [4] Four-char  [recommended]")
    wl_key = {"1":"5k","2":"20k","3":"110k","4":"4char"}[Prompt.ask("Choice", choices=["1","2","3","4"], default="4")]

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(f"vexRecon_{domain}_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    console.print(f"\n[dim]Output: {outdir}/[/dim]\n")

    # Wordlist
    wl_path = outdir / "wl.txt"
    console.print(f"[yellow]Downloading wordlist ({wl_key})...[/yellow]")
    if download(WORDLISTS[wl_key], wl_path):
        console.print("[green]✓ Wordlist ready.[/green]\n")
    else:
        wl_path.write_text("\n".join(BUILTIN_WL))
        console.print(f"[yellow]Using built-in wordlist ({len(BUILTIN_WL)} entries).[/yellow]\n")

    console.print(Panel(
        "[bold yellow]⚠  Port Scan Warning[/bold yellow]\n\n"
        "Port scanning without written permission may be [bold red]illegal[/bold red].\n"
        "IDS/IPS on the target may detect and log the scan.\n"
        "You are solely responsible for your use of this tool.",
        border_style="yellow"
    ))
    do_portscan = Confirm.ask("Run port scan with naabu?", default=False)

    console.print(f"\n[bold green]▶ Starting recon: {domain}[/bold green]\n")
    holder: dict = {}

    with Progress(
        SpinnerColumn(),
        BarColumn(bar_width=42),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing...", total=100)

        def recon_thread():
            r = run_recon(domain, tlds_file, outdir, str(wl_path), progress, task)
            holder.update(r)

        t = threading.Thread(target=recon_thread, daemon=True)
        t.start()
        t.join()
        progress.update(task, completed=100, description="[bold green]Done!")

    if wl_path.exists():
        wl_path.unlink()

    if do_portscan:
        console.print("\n[yellow]▶ Port scanning with naabu...[/yellow]")
        run_portscan(outdir, holder)
        # Re-write results.txt with port info included
        write_results(domain, holder, outdir)
        console.print("[green]✓ Port scan complete.[/green]")

    console.print(f"\n[bold green]✓ Done![/bold green]")
    console.print(f"\n  [bold cyan]{outdir}/results.txt[/bold cyan]   ← main output")
    console.print(f"  {outdir}/ips/<ip>/ptr.txt     ← reverse DNS per IP")
    console.print(f"  {outdir}/ips/<ip>/ssl.txt     ← SSL cert per IP")
    console.print(f"  {outdir}/ips/<ip>/vhosts.txt  ← virtual hosts per IP")
    console.print(f"  {outdir}/ips/<ip>/ports.txt   ← open ports per IP")
    console.print(f"  {outdir}/log.txt              ← run log")

    if holder.get("spf_warn"):
        console.print(Panel(
            f"[bold red]⚠  SPF WARNING — email spoofing may be possible for @{domain}[/bold red]",
            border_style="red"
        ))
    if holder.get("cdn"):
        cdn_list = "\n".join(f"  {ip} [{n}]" for ip, n in holder["cdn"].items())
        console.print(Panel(
            f"[bold yellow]CDN detected — real IP hidden:[/bold yellow]\n{cdn_list}\n\n"
            f"Shodan: https://www.shodan.io/search?query=ssl.cert.subject.cn%3A{domain}",
            border_style="yellow"
        ))
    if holder.get("takeover"):
        console.print(Panel(
            "[bold red]⚠  Subdomain Takeover candidates:[/bold red]\n" +
            "\n".join(f"  • {s}" for s in holder["takeover"]),
            border_style="red"
        ))


if __name__ == "__main__":
    main()
