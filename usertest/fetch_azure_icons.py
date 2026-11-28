# -*- coding: utf-8 -*-
"""Fetch the OFFICIAL Azure architecture icons (Microsoft Architecture Center) and rasterise the subset
this deck needs to 256px transparent PNGs under usertest/azure_icons/official/.

v1 of the deck used hand-drawn brand-style tiles because the download failed offline (2026-11-28 am);
the set downloads fine now, so v2 uses the real artwork under Microsoft's icon terms (use in
architecture diagrams / training / documentation; do not distort; name the product next to the icon).

Pipeline (all work in one fresh temp dir; the archive is untrusted input and is never executed):
  download Azure_Public_Service_Icons_V25.zip  ->  read ONLY the selected members out of the zip
  -> one HTML grid of <img> cells  ->  Edge headless screenshot (transparent background)
  -> PIL slices each 256x256 cell  ->  <key>.png + SOURCE.txt (provenance: URL, date, member names)

Usage:  python -I usertest/fetch_azure_icons.py [--zip C:/path/Azure_Public_Service_Icons_V25.zip]
        (--zip reuses an already-downloaded archive instead of downloading again)
"""
import argparse
import datetime
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from PIL import Image

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ICON_URL = "https://arch-center.azureedge.net/icons/Azure_Public_Service_Icons_V25.zip"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "azure_icons", "official")
CELL = 256
COLS = 6

# key -> ordered list of regexes tested against the member name (first match wins)
WANT = [
    ("container_apps", [r"other/02884-icon-service-Worker-Container-App\.svg$"]),
    ("container_apps_env", [r"other/02989-icon-service-Container-Apps-Environments\.svg$"]),
    ("acr", [r"containers/10105-icon-service-Container-Registries\.svg$"]),
    ("storage", [r"storage/10086-icon-service-Storage-Accounts\.svg$"]),
    ("files", [r"storage/10400-icon-service-Azure-Fileshares\.svg$"]),
    ("blob", [r"general/10780-icon-service-Blob-Block\.svg$"]),
    ("queue", [r"general/10840-icon-service-Storage-Queue\.svg$"]),
    ("log_analytics", [r"monitor/00009-icon-service-Log-Analytics-Workspaces\.svg$"]),
    ("monitor", [r"monitor/00001-icon-service-Monitor\.svg$"]),
    ("app_insights", [r"monitor/00012-icon-service-Application-Insights\.svg$"]),
    ("alerts", [r"management \+ governance/00002-icon-service-Alerts\.svg$"]),
    ("managed_identity", [r"identity/10227-icon-service-Managed-Identities\.svg$"]),
    # no base "Entra ID" icon exists in this archive (only ID Protection / roles / licences variants - checked
    # 2026-11-28), so per-user identity in the deck is drawn as a labelled chip rather than a wrong icon.
    ("key_vault", [r"security/10245-icon-service-Key-Vaults\.svg$"]),
    ("defender", [r"security/10241-icon-service-Microsoft-Defender-for-Cloud\.svg$"]),
    ("openai", [r"ai \+ machine learning/03438-icon-service-Azure-OpenAI\.svg$"]),
    ("front_door", [r"networking/10073-icon-service-Front-Door-and-CDN-Profiles\.svg$"]),
    ("waf", [r"networking/10362-icon-service-Web-Application-Firewall-Policies\(WAF\)\.svg$"]),
    ("vnet", [r"networking/10061-icon-service-Virtual-Networks\.svg$"]),
    ("private_link", [r"networking/00427-icon-service-Private-Link\.svg$"]),
    ("service_bus", [r"integration/10836-icon-service-Azure-Service-Bus\.svg$"]),
    ("cosmos", [r"databases/10121-icon-service-Azure-Cosmos-DB\.svg$"]),
    ("sql", [r"databases/10130-icon-service-SQL-Database\.svg$"]),
    ("backup", [r"other/02361-icon-service-Backup-Vault\.svg$"]),
    ("policy", [r"management \+ governance/10316-icon-service-Policy\.svg$"]),
    ("cost", [r"general/10019-icon-service-Cost-Management\.svg$"]),
    ("devops", [r"devops/10261-icon-service-Azure-DevOps\.svg$"]),
    ("api_management", [r"devops/10042-icon-service-API-Management-Services\.svg$"]),
    ("browser", [r"general/10783-icon-service-Browser\.svg$"]),
    ("resource_group", [r"general/10007-icon-service-Resource-Groups\.svg$"]),
    ("app_service", [r"containers/10035-icon-service-App-Services\.svg$"]),
    ("kubernetes", [r"containers/10023-icon-service-Kubernetes-Services\.svg$"]),
    ("container_instances", [r"containers/10104-icon-service-Container-Instances\.svg$"]),
    ("function_apps", [r"compute/10029-icon-service-Function-Apps\.svg$"]),
    ("event_grid", [r"integration/10206-icon-service-Event-Grid-Topics\.svg$"]),
]


def browser_paths():
    # Chrome's headless mode writes the screenshot before the process returns; Edge's launcher returns
    # first and finishes the file moments later (measured 2026-11-28) - hence the poll below either way.
    cands = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
             r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
             r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]
    found = [p for p in cands if os.path.isfile(p)]
    if not found:
        raise SystemExit("Chrome/Edge not found - cannot rasterise SVG icons")
    return found


def run_headless(cmd, shot):
    import time
    for exe in browser_paths():
        if os.path.exists(shot):
            os.remove(shot)
        subprocess.run([exe] + cmd, timeout=120, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(120):                       # up to 60s for the file to land
            if os.path.exists(shot) and os.path.getsize(shot) > 0:
                return exe
            time.sleep(0.5)
    raise SystemExit("headless screenshot failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default=None, help="reuse an already-downloaded archive")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="azure_icons_")
    try:
        zpath = os.path.join(work, "icons.zip")
        if args.zip and os.path.isfile(args.zip):
            shutil.copyfile(args.zip, zpath)
        else:
            with urllib.request.urlopen(ICON_URL, timeout=120) as resp, open(zpath, "wb") as fh:
                shutil.copyfileobj(resp, fh)
        zf = zipfile.ZipFile(zpath)
        names = zf.namelist()
        picked, missing = {}, []
        for key, pats in WANT:
            hit = None
            for pat in pats:
                hit = next((n for n in names if re.search(pat, n)), None)
                if hit:
                    break
            if hit is None:
                missing.append(key)
                continue
            # read only this member out; write it under a clean flat name
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", key) + ".svg"
            with zf.open(hit) as src, open(os.path.join(work, safe), "wb") as dst:
                shutil.copyfileobj(src, dst)
            picked[key] = (safe, hit)
        if missing:
            raise SystemExit("icons not found in archive: %s" % ", ".join(missing))
        # one grid page -> one headless screenshot -> PIL slices
        keys = [k for k, _ in WANT]
        rows = (len(keys) + COLS - 1) // COLS
        cells = "".join('<div class="c"><img src="%s"></div>' % picked[k][0] for k in keys)
        html = ("<!doctype html><meta charset=utf-8><style>body{margin:0;background:transparent}"
                ".c{width:%dpx;height:%dpx;float:left;overflow:hidden}"
                "img{width:%dpx;height:%dpx;display:block}</style>%s" % (CELL, CELL, CELL, CELL, cells))
        hpath = os.path.join(work, "grid.html")
        with open(hpath, "w", encoding="utf-8") as fh:
            fh.write(html)
        shot = os.path.join(work, "grid.png")
        cmd = ["--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
               "--no-default-browser-check", "--force-device-scale-factor=1",
               "--user-data-dir=" + os.path.join(work, "profile"),
               "--default-background-color=00000000",
               "--window-size=%d,%d" % (COLS * CELL, rows * CELL),
               "--screenshot=" + shot, "file:///" + hpath.replace("\\", "/")]
        used = run_headless(cmd, shot)
        sheet = Image.open(shot).convert("RGBA")
        os.makedirs(OUT, exist_ok=True)
        lines = ["# Official Azure architecture icons - rasterised subset (256x256 transparent PNG)",
                 "# Source: %s" % ICON_URL,
                 "# Fetched: %s   Tool: %s" % (datetime.date.today().isoformat(), os.path.basename(used)),
                 "# Terms: Microsoft permits use of these icons in architectural diagrams, training materials,",
                 "#        or documentation. Do not distort, crop, flip or rotate; name the product near the icon.",
                 "# key            <- zip member", ""]
        for i, k in enumerate(keys):
            x, y = (i % COLS) * CELL, (i // COLS) * CELL
            cell = sheet.crop((x, y, x + CELL, y + CELL))
            cell.save(os.path.join(OUT, k + ".png"), "PNG", optimize=True)
            lines.append("%-18s <- %s" % (k, picked[k][1]))
        with open(os.path.join(OUT, "SOURCE.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print("rasterised %d icons -> %s (sheet %dx%d)" % (len(keys), OUT, sheet.width, sheet.height))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
