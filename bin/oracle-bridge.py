#!/usr/bin/env python3
"""
Ponte somente leitura entre o PHP e o Oracle, usando python-oracledb em modo *thin*
(protocolo Oracle Net implementado em Python, sem Oracle Instant Client).

Protocolo: uma mensagem JSON por linha em stdin/stdout.
  1ª linha  -> {"host","port","service","user","password","timeout_ms","ssl"}
  resposta  <- {"ok": true, "version": "..."}  ou  {"ok": false, "error": "..."}
  depois    -> {"sql": "SELECT ...", "params": [...]}
  resposta  <- {"ok": true, "rows": [{coluna_minuscula: valor}, ...]}

A senha chega por stdin (nunca por argv/ambiente). Só SELECT/WITH são aceitos e a
transação é aberta com SET TRANSACTION READ ONLY e nunca recebe COMMIT.
"""
import datetime
import decimal
import json
import re
import sys

MAX_ROWS = 5000
MAX_LOB = 8000


def send(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def to_named(sql):
    """Troca placeholders '?' (fora de literais) por :1, :2, ..."""
    out, n, i, q = [], 0, 0, False
    while i < len(sql):
        c = sql[i]
        if c == "'":
            q = not q
        if c == "?" and not q:
            n += 1
            out.append(":%d" % n)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def conv(v):
    if v is None or isinstance(v, (str, bool)):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v) if v.is_integer() and abs(v) < 2 ** 53 else v
    if isinstance(v, decimal.Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat(sep=" ") if isinstance(v, datetime.datetime) else v.isoformat()
    if isinstance(v, datetime.timedelta):
        return v.total_seconds()
    if isinstance(v, (bytes, bytearray)):
        return v[:64].hex()
    if hasattr(v, "read"):  # LOB
        data = v.read(1, MAX_LOB)
        return conv(data)
    return str(v)


READ_ONLY = re.compile(r"^\s*(\(\s*)*(select|with)\b", re.I | re.S)


def main():
    try:
        import oracledb  # noqa: WPS433
    except Exception as e:  # pragma: no cover
        send({"ok": False, "error": "python-oracledb não instalado: %s" % e})
        return 2

    cfg = json.loads(sys.stdin.readline() or "{}")
    try:
        params = dict(
            user=cfg["user"], password=cfg.get("password") or "",
            host=cfg["host"], port=int(cfg.get("port") or 1521),
            service_name=cfg["service"], tcp_connect_timeout=8,
        )
        if cfg.get("ssl") in ("require", "verify-ca", "verify-full"):
            params["protocol"] = "tcps"
            params["ssl_server_dn_match"] = cfg.get("ssl") == "verify-full"
        conn = oracledb.connect(**params)
        conn.call_timeout = int(cfg.get("timeout_ms") or 15000)
        cur = conn.cursor()
        cur.execute("SET TRANSACTION READ ONLY")
        cur.close()
        send({"ok": True, "version": conn.version})
    except Exception as e:
        send({"ok": False, "error": str(e).strip()})
        return 1

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            sql = req["sql"]
            if not READ_ONLY.match(sql):
                raise ValueError("Somente SELECT/WITH são permitidos pelo analisador")
            cur = conn.cursor()
            cur.arraysize = 500
            cur.execute(to_named(sql), req.get("params") or [])
            cols = [d[0].lower() for d in cur.description or []]
            rows = []
            for r in cur:
                rows.append({c: conv(v) for c, v in zip(cols, r)})
                if len(rows) >= MAX_ROWS:
                    break
            cur.close()
            send({"ok": True, "rows": rows})
        except Exception as e:
            send({"ok": False, "error": str(e).strip()[:1000]})
    try:
        conn.rollback()
        conn.close()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
