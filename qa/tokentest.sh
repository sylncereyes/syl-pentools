#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
python3 - <<'PY'
import base64, json, os, urllib.request, urllib.error
tok = open(os.path.expanduser("~/.qa-auth/access_token")).read().strip()
h, p, s = tok.split(".")
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
pay = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
adm = b64(json.dumps(dict(pay, role="admin")).encode())
none = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
flip = s[:10] + ("A" if s[10] != "A" else "B") + s[11:]
def call(label, token):
    r = urllib.request.Request(os.environ["API_URL"] + "/api/auth/me")
    if token: r.add_header("Authorization", "Bearer " + token)
    try: c = urllib.request.urlopen(r, timeout=10).status
    except urllib.error.HTTPError as e: c = e.code
    except Exception as e: c = "ERR " + type(e).__name__
    print(f"{label:36} -> HTTP {c}")
call("token asli (harus 200)", tok)
call("tanpa token (harus 401)", "")
call("token sampah (harus 401)", "abc.def.ghi")
call("signature diubah (harus 401)", f"{h}.{p}.{flip}")
call("alg=none (harus 401)", f"{none}.{p}.")
call("alg=none + role admin (harus 401)", f"{none}.{adm}.")
call("payload role=admin, sig asli (401)", f"{h}.{adm}.{s}")
PY
