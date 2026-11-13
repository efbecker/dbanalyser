#!/usr/bin/env python3
"""
Gera data/vulndb.json — base OFFLINE de vulnerabilidades e ciclo de vida dos SGBDs suportados.

Fontes (todas públicas, baixadas do GitHub para funcionar mesmo onde a API do NVD é instável):
  - CVEs: NVD (configurações CPE analisadas) + dados "affected" do CNA (PostgreSQL, Oracle, Microsoft,
    MariaDB), via espelho fkie-cad/nvd-json-data-feeds (feeds anuais, atualizados diariamente).
    O fallback do CNA cobre CVEs recentes que o NVD ainda não analisou.
  - Ciclo de vida (EOL, última versão de cada ciclo): endoflife-date/endoflife.date e release-data.

Uso:  python3 tools/build_vulndb.py [--cache DIR] [--from-year 2012] [--out data/vulndb.json]
Requer Python 3.9+ e PyYAML. O analisador lê apenas o JSON gerado: nada é consultado na internet
durante uma análise.
"""
import argparse, datetime as dt, json, lzma, os, re, sys, urllib.request

import yaml

FEED = 'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{y}.json.xz'
EOL_MD = 'https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/{p}.md'
EOL_REL = 'https://raw.githubusercontent.com/endoflife-date/release-data/main/releases/{p}.json'

# motor -> (produto endoflife.date, CPEs vendor:product do NVD, predicado do produto no bloco "affected" do CNA)
ENGINES = {
    'postgresql': ('postgresql', {'postgresql:postgresql'},
                   lambda v, p: p == 'postgresql' and v in ('n/a', 'postgresql', 'postgresql global development group')),
    'mysql': ('mysql', {'oracle:mysql', 'oracle:mysql_server', 'mysql:mysql', 'mysql:mysql_community_server'},
              lambda v, p: v.startswith('oracle') and p == 'mysql server'),
    'mariadb': ('mariadb', {'mariadb:mariadb'},
                lambda v, p: v == 'mariadb' and p in ('server', 'mariadb', 'mariadb server')),
    'sqlserver': ('mssqlserver', {f'microsoft:sql_server_{y}' for y in (2012, 2014, 2016, 2017, 2019, 2022, 2025)} | {'microsoft:sql_server'},
                  lambda v, p: v == 'microsoft' and re.match(r'^(microsoft )?sql server 20\d\d\b', p) is not None
                  and not re.search(r'management studio|reporting|integration|analysis|native client|odbc|ole db|jdbc', p)),
    'oracle': ('oracle-database', {'oracle:database_server', 'oracle:database'},
               lambda v, p: v.startswith('oracle') and p in ('oracle database server', 'database server', 'oracle database')),
}

# O CVE precisa citar o produto na descrição: o NVD às vezes marca o MySQL como afetado por bibliotecas
# empacotadas em outros produtos Oracle (libcurl, XStream...) — sem isso viram falsos positivos.
MENTIONS = {
    'postgresql': r'postgres', 'mysql': r'mysql', 'mariadb': r'mariadb|mysql',
    'sqlserver': r'sql server', 'oracle': r'oracle database|database server|rdbms|oracle net|oracle text|java vm|oracle spatial|clusterware',
}

# Extensões do PostgreSQL com CVEs próprios (nome em pg_extension -> CPEs / produto no CNA)
PG_EXTENSIONS = {
    'postgis': ({'postgis:postgis', 'osgeo:postgis'}, lambda v, p: p == 'postgis'),
    'timescaledb': ({'timescale:timescaledb'}, lambda v, p: p == 'timescaledb'),
    'anon': ({'dalibo:postgresql_anonymizer'}, lambda v, p: p == 'postgresql anonymizer'),
    'citus': ({'citusdata:citus'}, lambda v, p: p == 'citus'),
    'pg_cron': ({'citusdata:pg_cron'}, lambda v, p: p == 'pg_cron'),
    'pgaudit': ({'pgaudit:pgaudit'}, lambda v, p: p == 'pgaudit'),
    'vector': ({'pgvector:pgvector'}, lambda v, p: p == 'pgvector'),
    'pg_repack': ({'reorg:pg_repack'}, lambda v, p: p == 'pg_repack'),
}

NUM = re.compile(r'^\d+(\.\d+)*$')


def fetch(url, dest):
    if not os.path.exists(dest):
        print('  baixando', url, file=sys.stderr)
        req = urllib.request.Request(url, headers={'User-Agent': 'db-analyzer-vulndb'})
        with urllib.request.urlopen(req, timeout=600) as r, open(dest + '.tmp', 'wb') as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        os.replace(dest + '.tmp', dest)
    return dest


def norm(v):
    """Normaliza para dígitos e pontos ('8.0.36-log' -> '8.0.36'); None se não for numérico."""
    if v is None:
        return None
    v = str(v).strip().lstrip('vV')
    m = re.match(r'^(\d+(?:\.\d+)*)', v)
    if not m:
        return None
    return m.group(1)


def vkey(v):
    return tuple(int(x) for x in v.split('.'))


def bump(v):
    """Primeira versão posterior a um limite inclusivo: 8.0.42 -> 8.0.43, 19.27 -> 19.28."""
    p = v.split('.')
    p[-1] = str(int(p[-1]) + 1)
    return '.'.join(p)


def nvd_ranges(cve, products):
    out = []
    for conf in cve.get('configurations', []) or []:
        for node in conf.get('nodes', []):
            for m in node.get('cpeMatch', []):
                if not m.get('vulnerable'):
                    continue
                parts = m['criteria'].split(':')
                if len(parts) < 6 or f'{parts[3]}:{parts[4]}' not in products:
                    continue
                exact = parts[5]
                si, se = norm(m.get('versionStartIncluding')), norm(m.get('versionStartExcluding'))
                ei, ee = norm(m.get('versionEndIncluding')), norm(m.get('versionEndExcluding'))
                if exact not in ('*', '-'):
                    e = norm(exact.replace('\\', ''))
                    if e and NUM.match(exact.replace('\\', '')) and not (si or se or ei or ee):
                        out.append([e, 1, e, 1])
                    continue
                if not (si or se or ei or ee):
                    continue  # "todas as versões" sem limite: amplo demais, gera falso positivo
                lo, loi = (si, 1) if si else ((se, 0) if se else (None, 1))
                hi, hii = (ei, 1) if ei else ((ee, 0) if ee else (None, 1))
                out.append([lo, loi, hi, hii])
    return out


RANGE_TXT = re.compile(r'^\s*>=?\s*([\d.]+)\s*,\s*<(=?)\s*([\d.]+)\s*$')


def cna_ranges(cve, pred):
    out = []
    for a in cve.get('affected', []) or []:
        for ad in a.get('affectedData', []) or []:
            v = (ad.get('vendor') or '').strip().lower()
            p = (ad.get('product') or '').strip().lower()
            if not pred(v, p):
                continue
            for ver in ad.get('versions', []) or []:
                if ver.get('status') != 'affected':
                    continue
                raw = str(ver.get('version') or '').strip()
                if ver.get('lessThan') or ver.get('lessThanOrEqual'):
                    hi = norm(ver.get('lessThan') or ver.get('lessThanOrEqual'))
                    lo = norm(raw) if raw not in ('', '*', 'n/a') else None
                    if hi:
                        out.append([lo if lo and lo != '0' else None, 1, hi, 0 if ver.get('lessThan') else 1])
                    continue
                m = re.match(r'^([\d.]+)\s*-\s*([\d.]+)$', raw)          # Oracle: "8.4.0-8.4.12"
                if m:
                    out.append([m.group(1), 1, m.group(2), 1])
                    continue
                m = RANGE_TXT.match(raw)                                # MariaDB: ">= 10.11.1, < 10.11.19"
                if m:
                    out.append([m.group(1), 1 if '>=' in raw else 0, m.group(3), 1 if m.group(2) else 0])
                    continue
                m = re.match(r'^<(=?)\s*([\d.]+)$', raw)
                if m:
                    out.append([None, 1, m.group(2), 1 if m.group(1) else 0])
                    continue
                if NUM.match(raw) and raw.count('.') >= 1:
                    out.append([raw, 1, raw, 1])
    return out


def cvss(cve):
    ms = cve.get('metrics', {}) or {}
    for k in ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'):
        lst = ms.get(k) or []
        lst = sorted(lst, key=lambda x: x.get('type') != 'Primary')
        for x in lst:
            d = x.get('cvssData', {})
            score = d.get('baseScore')
            sev = d.get('baseSeverity') or x.get('baseSeverity')
            if score is not None:
                return float(score), (sev or '').lower() or None
    return None, None


def summary(cve):
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            t = re.sub(r'\s+', ' ', d['value']).strip()
            # Oracle repete um parágrafo padrão longo; mantém só a primeira frase útil
            t = re.sub(r'^Vulnerability in the (MySQL Server|Oracle Database Server|Oracle Database) product of Oracle (MySQL|Database Server)?\s*', '', t)
            return t[:260] + ('…' if len(t) > 260 else '')
    return ''


def dedupe(rs):
    seen, out = set(), []
    for r in rs:
        t = tuple(r)
        if t not in seen:
            seen.add(t)
            out.append(r)
    return out


def eol_data(cache, prod):
    md = open(fetch(EOL_MD.format(p=prod), os.path.join(cache, prod + '.md')), encoding='utf-8').read()
    front = yaml.safe_load(md.split('---')[1])
    try:
        rel = json.load(open(fetch(EOL_REL.format(p=prod), os.path.join(cache, prod + '.rel.json'))))
        versions = sorted({norm(k) for k in rel.get('versions', {}) if norm(k)}, key=vkey)
    except Exception:
        versions = []
    cycles = []
    for r in front.get('releases', []):
        c = {'cycle': str(r['releaseCycle'])}
        for k in ('releaseLabel', 'releaseDate', 'eoas', 'eol', 'eoes', 'lts', 'latest', 'latestReleaseDate', 'latestGdr'):
            if k in r and r[k] is not None:
                v = r[k]
                c[k] = v.isoformat() if isinstance(v, (dt.date, dt.datetime)) else v
        if 'latest' in c:
            c['latest'] = str(c['latest'])
            n = norm(c['latest'])
            # a release-data pode estar à frente do arquivo de produto (release de hoje)
            same = [v for v in versions if v.startswith(c['cycle'] + '.')]
            if n and same and vkey(same[-1]) > vkey(n):
                c['latest'] = same[-1]
        cycles.append(c)
    return {'product': prod, 'cycles': cycles, 'versions': versions}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache', default=os.path.join(os.path.dirname(__file__), '..', 'storage', 'vulndb-cache'))
    ap.add_argument('--from-year', type=int, default=2012)
    ap.add_argument('--out', default=os.path.join(os.path.dirname(__file__), '..', 'data', 'vulndb.json'))
    args = ap.parse_args()
    os.makedirs(args.cache, exist_ok=True)
    year = dt.date.today().year

    engines = {e: {'cves': {}} for e in ENGINES}
    exts = {x: {'cves': {}} for x in PG_EXTENSIONS}
    feed_ts = None
    for y in range(args.from_year, year + 1):
        path = fetch(FEED.format(y=y), os.path.join(args.cache, f'CVE-{y}.json.xz'))
        data = json.load(lzma.open(path))
        feed_ts = max(feed_ts or '', data.get('timestamp', ''))
        for cve in data['cve_items']:
            if cve.get('vulnStatus') == 'Rejected':
                continue
            desc = ' '.join(d.get('value', '') for d in cve.get('descriptions', []) if d.get('lang') == 'en').lower()
            targets = [(e, engines[e]['cves'], prods, pred) for e, (_, prods, pred) in ENGINES.items()]
            targets += [(None, exts[x]['cves'], prods, pred) for x, (prods, pred) in PG_EXTENSIONS.items()]
            for eng, bucket, prods, pred in targets:
                rs = dedupe(nvd_ranges(cve, prods) + cna_ranges(cve, pred))
                if not rs or (eng and not re.search(MENTIONS[eng], desc)):
                    continue
                if eng == 'sqlserver':
                    # NVD separa por produto (sql_server_2019, _2022...), mas aqui é um só motor: um limite
                    # inferior aberto vale só dentro do mesmo major (ex.: < 16.0.1200.5 => >= 16.0)
                    rs = dedupe([[r[0] if r[0] and r[0] != '0' else ('.'.join(r[2].split('.')[:2]) if r[2] else None), r[1], r[2], r[3]] for r in rs])
                score, sev = cvss(cve)
                item = {'id': cve['id'], 'cvss': score, 'sev': sev, 'pub': (cve.get('published') or '')[:10], 'sum': summary(cve), 'r': rs}
                if cve.get('cisaExploitAdd'):
                    item['kev'] = cve['cisaExploitAdd']
                bucket[cve['id']] = item

    out = {
        'format': 1,
        'generated_at': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'nvd_feed_at': feed_ts,
        'sources': {
            'cves': 'NVD + CNA (via github.com/fkie-cad/nvd-json-data-feeds)',
            'lifecycle': 'endoflife.date (github.com/endoflife-date)',
        },
        'engines': {},
        'pg_extensions': {},
    }
    for e, (prod, _, _) in ENGINES.items():
        life = eol_data(args.cache, prod)
        out['engines'][e] = life | {'cves': sorted(engines[e]['cves'].values(), key=lambda c: c['id'])}
        print(f'{e}: {len(engines[e]["cves"])} CVEs, {len(life["cycles"])} ciclos', file=sys.stderr)
    for x in PG_EXTENSIONS:
        out['pg_extensions'][x] = {'cves': sorted(exts[x]['cves'].values(), key=lambda c: c['id'])}
        print(f'ext {x}: {len(exts[x]["cves"])} CVEs', file=sys.stderr)

    # Um CVE por linha: diffs legíveis no git a cada atualização
    tmp = args.out + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        txt = json.dumps(out, ensure_ascii=False, separators=(',', ':'))
        txt = txt.replace(',{"id":"CVE-', ',\n{"id":"CVE-').replace('[{"id":"CVE-', '[\n{"id":"CVE-')
        f.write(txt + '\n')
    os.replace(tmp, args.out)
    print('gravado', args.out, os.path.getsize(args.out), 'bytes', file=sys.stderr)


if __name__ == '__main__':
    main()
