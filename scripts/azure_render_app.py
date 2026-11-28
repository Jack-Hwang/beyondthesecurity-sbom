"""Render the Container Apps declaration (deploy/azure/containerapp.yaml) for one deployment (BSA-AC-1224).

The template keeps placeholders instead of values; this script fills them from the ENVIRONMENT (secrets are never printed
and never written anywhere but the output file), adds the registry credentials block with an explicit passwordSecretRef,
scales to zero for the demo cost cap and writes a pure-ASCII file (az reads YAML with the Windows ANSI code page, so a
Korean comment makes `az containerapp create --yaml` fail with a cp949 decode error). Delete the output right after
`az containerapp create`: it holds the secrets.

usage: python -I scripts/azure_render_app.py <template> <out>
env:   IMAGE FQDN LLM_KEY LLM_BASE ACCESS_TOKEN ACR_SERVER ACR_USER ACR_PASSWORD   (optional: WEEK, OWNER, MIN_REPLICAS, IMAGE_DIGEST)
       IMAGE_DIGEST (C35): an immutable sha256 digest for the same repository - when set, IMAGE must name the SAME
       repository and the rendered image becomes repo@sha256:... instead of a mutable tag.
"""
import os
import re
import sys

tpl, out = sys.argv[1], sys.argv[2]
s = open(tpl, encoding="utf-8").read().replace("\r\n", "\n")


def sub(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)


E = os.environ
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = E["IMAGE"]
if E.get("IMAGE_DIGEST"):
    d = E["IMAGE_DIGEST"].strip()
    if not DIGEST.fullmatch(d):
        sys.exit("IMAGE_DIGEST must be sha256:<64 hex>, got %r" % d)
    if "@" in IMAGE:
        sys.exit("IMAGE must be a plain repo[:tag] when IMAGE_DIGEST is set; got %r" % IMAGE)
    repo = IMAGE.rsplit(":", 1)[0] if ":" in IMAGE else IMAGE
    IMAGE = "%s@%s" % (repo, d)                        # C35: the mutable tag is replaced by the immutable digest
sub('week: "<ISO week of this redeploy, e.g. 2026-W48>"', 'week: "%s"' % E.get("WEEK", "2026-W48"))
sub('owner: "<on-call contact: email or chat handle>"', 'owner: "%s"' % E.get("OWNER", "bts-sbom-operator"))
sub('value: "<AZURE_OPENAI_KEY — az keyvault 또는 수동 입력>"', 'value: "%s"' % E["LLM_KEY"])
sub('value: "https://<resource>.openai.azure.com"', 'value: "%s"' % E["LLM_BASE"])
sub('value: "<python -m bts_sbom_app access-token 으로 만든 값 — 로그·레포에 남기지 말 것>"', 'value: "%s"' % E["ACCESS_TOKEN"])
sub('image: "<REGISTRY>/bts-sbom-app:8.1.0"   # Dockerfile.bts-sbom-app 빌드 결과', 'image: "%s"' % IMAGE)
sub('value: "<app FQDN, 예: bts-sbom.<env>.azurecontainerapps.io>"', 'value: "%s"' % E["FQDN"])
sub("      minReplicas: 1                       # 단일 프로세스·evidence 공유 계약 — 0 스케일 배제", "      minReplicas: %s                       # 0 = demo cost cap (scale to zero when idle); az containerapp update --min-replicas 1 pins one" % E.get("MIN_REPLICAS", "0"))
# the OSV snapshot lives on the evidence volume (seed) and is copied to LOCAL disk at start-up: SQLite cannot take the scanner's concurrent writes on an SMB share (AC-1226)
sub('''          - name: BTS_SBOM_UNICODE
            value: "1"
''', '''          - name: BTS_SBOM_UNICODE
            value: "1"
          - name: BTS_SBOM_OSV_DB_PATH
            value: "/tmp/osvdb/bts_sbom_osv_local.db"
          - name: BTS_SBOM_OSV_SEED_DB
            value: "/tmp/evidence/bts_sbom_osv_local.db"
''')
# registry credentials: an explicit passwordSecretRef (the auto-generated secret name of --registry-password is invalid on this CLI)
sub('''    secrets:
      - name: azure-api-key''', '''    registries:
      - server: "%s"
        username: "%s"
        passwordSecretRef: acr-password
    secrets:
      - name: acr-password
        value: "%s"
      - name: azure-api-key''' % (E["ACR_SERVER"], E["ACR_USER"], E["ACR_PASSWORD"]))
s = 'location: koreacentral\n' + s
# az reads the file with the Windows ANSI code page: keep the rendered file pure ASCII (drop non-ASCII comments)
clean = []
for line in s.split("\n"):
    if any(ord(c) > 127 for c in line):
        i = line.find("#")
        line = line[:i].rstrip() if i >= 0 else line
        if not line.strip():
            continue
    clean.append(line)
s = "\n".join(clean) + "\n"
assert all(ord(c) < 128 for c in s), "non-ASCII left in the rendered YAML"
open(out, "w", encoding="utf-8", newline="\n").write(s)
print("rendered", len(s), "chars")
