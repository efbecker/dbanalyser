"""
Tradução determinística (offline, sem IA) das descrições de CVE que seguem texto padrão do fabricante:
  - Oracle (MySQL e Oracle Database): "Vulnerability in the ... Easily exploitable vulnerability allows ..."
  - Microsoft: títulos ("Microsoft SQL Server Remote Code Execution Vulnerability") e frases no formato CWE
    ("Heap-based buffer overflow in SQL Server allows an authorized attacker to execute code over a network.")
Devolve None quando alguma frase não é reconhecida: nesse caso o analisador usa a tradução da IA (com cache)
ou o texto original. Nunca traduz pela metade.
"""
import re

PRIV = {
    'unauthenticated': 'sem autenticação',
    'low privileged': 'com poucos privilégios',
    'high privileged': 'com privilégios elevados',
}

IMPACTS = [
    (r'takeover of (.+)', lambda m: f'tomada de controle do {m[1]}'),
    (r'unauthorized ability to cause a hang or frequently repeatable crash \(complete DOS\) of (.+)',
     lambda m: f'travamento ou queda repetível (negação de serviço completa) do {m[1]}'),
    (r'unauthorized ability to cause a partial denial of service \(partial DOS\) of (.+)',
     lambda m: f'negação de serviço parcial do {m[1]}'),
    (r'unauthorized read access to a subset of (.+?) accessible data',
     lambda m: f'leitura não autorizada de parte dos dados acessíveis pelo {m[1]}'),
    (r'unauthorized update, insert or delete access to some of (.+?) accessible data',
     lambda m: f'alteração, inclusão ou exclusão não autorizada de parte dos dados do {m[1]}'),
    (r'unauthorized access to critical data or complete access to all (.+?) accessible data',
     lambda m: f'acesso não autorizado a dados críticos ou a todos os dados do {m[1]}'),
    (r'unauthorized creation, deletion or modification access to critical data or all (.+?) accessible data',
     lambda m: f'criação, exclusão ou alteração não autorizada de dados críticos ou de todos os dados do {m[1]}'),
]


def _impact(txt):
    txt = re.sub(r'\s+', ' ', txt).strip().rstrip('.')
    parts = re.split(r' as well as | and (?=unauthorized|takeover)', txt)
    out = []
    for p in parts:
        p = p.strip()
        for rx, fn in IMPACTS:
            m = re.fullmatch(rx, p)
            if m:
                out.append(fn(m))
                break
        else:
            return None
    return '; '.join(out)


def _vector(v):
    v = v.strip()
    m = re.fullmatch(r'network access via multiple protocols', v)
    if m:
        return 'acesso à rede (vários protocolos)'
    m = re.fullmatch(r'network access via (.+)', v)
    if m:
        return f'acesso à rede via {m[1]}'
    m = re.fullmatch(r'logon to the infrastructure where (.+?) executes', v)
    if m:
        return f'acesso local ao servidor onde o {m[1]} roda'
    m = re.fullmatch(r'access to the physical communication segment attached to the hardware where (?:the )?(.+?) executes', v)
    if m:
        return f'acesso ao segmento físico de rede do servidor onde o {m[1]} roda'
    return None


def oracle(desc):
    d = re.sub(r'\s+', ' ', desc.replace('"exploitable"', 'exploitable')).strip()
    if not d.startswith('Vulnerability in the'):
        return None
    comp = None
    m = re.match(r'Vulnerability in the (.+?) (?:product|component) of Oracle [\w ]+?(?: \((?:sub)?component: ([^)]+)\))?\.', d)
    if not m:
        return None
    comp = m[2] or m[1]
    rest = d[m.end():].strip()
    out = [f'Componente: {comp}.']
    # frases restantes
    sentences = re.split(r'(?<=\.)\s+(?=[A-Z])', rest)
    for s in sentences:
        s = s.strip()
        if not s or re.match(r'(Supported versions? that (?:are|is) affected (?:are|is)|The supported version that is affected is|CVSS (?:v?[\d.]+ )?(?:Base Score|Vector)|Note:|NOTE:|Applies to|For Windows platform|On non-Windows platforms)', s):
            continue
        m = re.fullmatch(r'(Easily|Difficult to) exploit(?:able)? vulnerability allows (unauthenticated|low privileged|high privileged) attacker'
                         r'(?: having (.+?) privilege)? with (.+?) to compromise (.+?)\.', s)
        if m:
            vec = _vector(m[4])
            if not vec:
                return None
            priv = PRIV[m[2]] + (f' (privilégio {m[3]})' if m[3] else '')
            out.append(f"Exploração {'fácil' if m[1] == 'Easily' else 'difícil'} por atacante {priv}, com {vec}.")
            continue
        if re.fullmatch(r'Successful attacks require human interaction from a person other than the attacker(?: and while the vulnerability is in .+?, attacks may significantly impact additional products(?: \(scope change\))?)?\.', s):
            out.append('Exige interação de outra pessoa.')
            continue
        if re.fullmatch(r'While the vulnerability is in .+?, attacks may significantly impact additional products(?: \(scope change\))?\.', s):
            out.append('O ataque pode afetar outros produtos.')
            continue
        m = re.fullmatch(r'Successful attacks of this vulnerability can result in (.+)\.', s)
        if m:
            imp = _impact(m[1])
            if not imp:
                return None
            out.append(f'Impacto: {imp}.')
            continue
        return None
    return ' '.join(out) if len(out) > 1 else None


MS_TITLE = {
    'Remote Code Execution': 'execução remota de código',
    'Elevation of Privilege': 'elevação de privilégio',
    'Information Disclosure': 'divulgação de informações',
    'Denial of Service': 'negação de serviço',
    'Security Feature Bypass': 'desvio de recurso de segurança',
    'Spoofing': 'falsificação (spoofing)',
    'Tampering': 'adulteração de dados',
}


def microsoft_title(desc):
    m = re.fullmatch(r'(.+?) (Remote Code Execution|Elevation of Privilege|Information Disclosure|Denial of Service|Security Feature Bypass|Spoofing|Tampering) Vulnerability\.?', desc.strip())
    if not m or not re.search(r'SQL|OLE DB|ODBC', m[1]):
        return None
    return f'Vulnerabilidade de {MS_TITLE[m[2]]} no {m[1]}.'


WEAKNESS = {
    'heap-based buffer overflow': 'Estouro de buffer na heap',
    'stack-based buffer overflow': 'Estouro de buffer na pilha',
    'buffer over-read': 'Leitura além do limite do buffer',
    'out-of-bounds read': 'Leitura fora dos limites da memória',
    'out-of-bounds write': 'Escrita fora dos limites da memória',
    'use after free': 'Uso de memória após liberação (use after free)',
    'double free': 'Liberação dupla de memória (double free)',
    'integer overflow or wraparound': 'Estouro de inteiro',
    'integer underflow (wrap or wraparound)': 'Subfluxo de inteiro',
    'use of uninitialized resource': 'Uso de recurso não inicializado',
    'deserialization of untrusted data': 'Desserialização de dados não confiáveis',
    'improper access control': 'Controle de acesso inadequado',
    'improper authorization': 'Autorização inadequada',
    'improper authentication': 'Autenticação inadequada',
    'missing authentication for critical function': 'Ausência de autenticação em função crítica',
    'missing authorization': 'Ausência de verificação de autorização',
    'incorrect authorization': 'Autorização incorreta',
    'improper input validation': 'Validação de entrada inadequada',
    'improper validation of specified type of input': 'Validação inadequada do tipo de entrada',
    'untrusted pointer dereference': 'Uso de ponteiro não confiável',
    'null pointer dereference': 'Uso de ponteiro nulo',
    'type confusion': 'Confusão de tipos',
    'insufficient granularity of access control': 'Controle de acesso pouco granular',
    'execution with unnecessary privileges': 'Execução com privilégios desnecessários',
    'origin validation error': 'Falha na validação de origem',
    "improper control of generation of code ('code injection')": 'Injeção de código',
    "improper neutralization of special elements used in an sql command ('sql injection')": 'Injeção de SQL',
    'external control of file name or path': 'Controle externo de nome ou caminho de arquivo',
    'use of a broken or risky cryptographic algorithm': 'Uso de algoritmo criptográfico fraco',
    'exposure of sensitive information to an unauthorized actor': 'Exposição de informação sensível',
    'concurrent execution using shared resource with improper synchronization (\'race condition\')': 'Condição de corrida',
    'uncontrolled resource consumption': 'Consumo descontrolado de recursos',
    'access of resource using incompatible type (\'type confusion\')': 'Confusão de tipos',
    'relative path traversal': 'Travessia de diretório (path traversal)',
    'improper privilege management': 'Gestão inadequada de privilégios',
}

ACTION = {
    'execute code': 'executar código',
    'elevate privileges': 'elevar privilégios',
    'disclose information': 'obter informações sigilosas',
    'deny service': 'causar negação de serviço',
    'perform spoofing': 'se passar por outra entidade',
    'bypass a security feature': 'contornar um recurso de segurança',
    'perform tampering': 'adulterar dados',
}

WHO = {
    'an unauthorized attacker': 'um atacante sem autorização',
    'an unauthenticated attacker': 'um atacante sem autenticação',
    'an authorized attacker': 'um atacante autenticado',
    'an authenticated attacker': 'um atacante autenticado',
}


def cwe_style(desc):
    m = re.fullmatch(r'(.+?) in (SQL Server|Microsoft SQL Server|SQL Server [\w ]+?) allows (an? [\w ]+?attacker) to ([\w ]+?) (over a network|locally)\.', desc.strip())
    if not m:
        return None
    w, who, act = WEAKNESS.get(m[1].lower()), WHO.get(m[3]), ACTION.get(m[4])
    if not (w and who and act):
        return None
    onde = 'pela rede' if m[5] == 'over a network' else 'localmente'
    return f'{w} no {m[2]} permite que {who} consiga {act} {onde}.'


def translate(desc):
    """Tradução por regras ou None."""
    if not desc:
        return None
    for fn in (oracle, microsoft_title, cwe_style):
        try:
            r = fn(desc)
        except Exception:
            r = None
        if r:
            return r
    return None
