from __future__ import annotations

import hashlib
import io
import re
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import CollectorRegistry, Counter, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="ZORBOX Static Analyzer", version="0.2.0")

registry = CollectorRegistry()
jobs_processed = Counter("analyzer_jobs_processed_total", "Static analyzer jobs processed", registry=registry)
yara_hit_counter = Counter("analyzer_yara_hits_total", "YARA hits", registry=registry)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sniff_type(name: Optional[str], data: bytes) -> str:
    fn = (name or '').lower()
    # magic-first for common formats
    if data[:4] == b'\x7fELF':
        return 'elf'
    if data.startswith(b'%PDF'):
        return 'pdf'
    if data[:4] == b'PK\x03\x04':
        return 'zip'
    # extension-based
    if fn.endswith('.ps1'): return 'ps1'
    if fn.endswith('.js'): return 'js'
    if any(fn.endswith(x) for x in ('.doc', '.docm', '.docx', '.xls', '.xlsx', '.ppt', '.pptm', '.pptx')):
        return 'office'
    if fn.endswith('.exe') or fn.endswith('.dll'): return 'pe'
    if fn.endswith('.apk'): return 'apk'
    if fn.endswith('.jar'): return 'jar'
    if fn.endswith('.zip'): return 'zip'
    if fn.endswith('.vbs'): return 'vbs'
    if fn.endswith('.bat') or fn.endswith('.cmd'): return 'bat'
    if fn.endswith('.py'): return 'py'
    if fn.endswith('.bin') or fn.endswith('.elf'): return 'elf'
    return 'unknown'


def heuristics(ftype: str, text: str) -> Dict[str, Any]:
    h: Dict[str, Any] = {}
    # Common URLs
    urls = re.findall(r'https?://[\w\.-/%\+\?_#=&]+', text)[:10]
    if urls:
        h['urls_found'] = urls

    if ftype == 'ps1':
        h['encoded_command'] = bool(re.search(r'-enc(odedcommand)?\b', text, re.I))
        h['suspicious_cmdlets'] = bool(re.search(r'(Invoke-WebRequest|Invoke-Expression|Add-MpPreference|New-Object\s+Net\.WebClient)', text, re.I))

    if ftype == 'js':
        h['uses_eval'] = 'eval(' in text
        h['uses_unescape'] = 'unescape(' in text
        h['obfuscation_tokens'] = any(tok in text for tok in ('String.fromCharCode(', 'atob(', 'document.write('))

    if ftype == 'pdf':
        h['openaction'] = '/OpenAction' in text
        h['has_js'] = '/JS' in text

    if ftype == 'office':
        h['macro_tokens'] = bool(re.search(r'(Sub\s+AutoOpen|CreateObject|Declare PtrSafe|ThisDocument)', text, re.I))

    if ftype == 'vbs':
        h['wscript_shell'] = bool(re.search(r'CreateObject\(\s*["\']WScript\.Shell["\']\s*\)', text, re.I))
        h['shell_exec'] = bool(re.search(r'\bShell\(', text, re.I))
        h['spawn_powershell'] = bool(re.search(r'\bpowershell(\.exe)?\b', text, re.I))
        h['uses_mshta'] = bool(re.search(r'\bmshta(\.exe)?\b', text, re.I))

    if ftype == 'bat':
        h['uses_curl_wget'] = bool(re.search(r'\b(curl|wget)\b', text, re.I))
        h['uses_certutil'] = bool(re.search(r'\bcertutil(\.exe)?\b.+-urlcache', text, re.I))
        h['spawns_powershell'] = bool(re.search(r'\bpowershell(\.exe)?\b', text, re.I))
        h['modifies_startup'] = bool(re.search(r'AppData\\\\[^\\\r\n]+\\\\Startup', text, re.I))

    if ftype == 'py':
        h['uses_subprocess'] = bool(re.search(r'\bimport\s+subprocess\b|\bsubprocess\.', text))
        h['uses_os_system'] = bool(re.search(r'\bos\.system\(', text))
        h['networking'] = bool(re.search(r'\b(requests|urllib|socket)\b', text))
        h['base64_decode'] = bool(re.search(r'\bbase64\.b64decode\(', text))

    if ftype == 'elf':
        h['networking'] = bool(re.search(r'\b(getaddrinfo|connect|socket)\b', text))
        h['suspicious_cmd'] = bool(re.search(r'\b(/bin/sh|/bin/bash|busybox)\b', text))
        h['crypto_apis'] = bool(re.search(r'\b(AES|EVP_|libcrypto)\b', text))

    return h


def analyze_pe(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
        arch = 'pe32+' if pe.OPTIONAL_HEADER.Magic == 0x20B else 'pe32'
        ts = getattr(pe.FILE_HEADER, 'TimeDateStamp', None)
        sections: List[Dict[str, Any]] = []
        def entropy(b: bytes) -> float:
            import math
            if not b:
                return 0.0
            from collections import Counter
            c = Counter(b)
            total = len(b)
            return -sum((n/total)*math.log2(n/total) for n in c.values())
        for s in pe.sections[:10]:
            name = s.Name.rstrip(b'\x00').decode('utf-8', 'ignore')
            ch = getattr(s, 'Characteristics', 0)
            sec = {
                'name': name,
                'size': int(s.SizeOfRawData or 0),
                'entropy': float(entropy(s.get_data()[:4096])),
                'rwx': bool((ch & 0x20000000) and (ch & 0x80000000)),  # EXECUTE+WRITE
            }
            sections.append(sec)
        imports_top: List[str] = []
        suspicious_imports: List[str] = []
        try:
            suspicious_set = {
                'WinExec','ShellExecuteA','ShellExecuteW','CreateRemoteThread','VirtualAlloc','VirtualProtect',
                'WriteProcessMemory','URLDownloadToFileA','URLDownloadToFileW','InternetOpenA','InternetOpenW',
                'InternetConnectA','InternetConnectW','WSAStartup','socket','connect','recv','send'
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:
                    dll = entry.dll.decode('utf-8', 'ignore') if entry.dll else 'unknown'
                    funcs = []
                    for imp in entry.imports[:5]:
                        fname = imp.name.decode('utf-8', 'ignore') if imp.name else 'ord'
                        funcs.append(fname)
                        if fname in suspicious_set:
                            suspicious_imports.append(f"{dll}!{fname}")
                    imports_top.append(f"{dll}:" + ",".join(funcs))
        except Exception:
            pass
        exports_count = 0
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
                exports_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols or [])
        except Exception:
            pass
        packer_flags = any(n for n in (sec.get('name','').lower() for sec in sections) if any(p in n for p in ('upx', 'aspack', 'mpress')))
        rwx_sections = [s['name'] for s in sections if s.get('rwx')]
        # Security directory (signature) presence (best-effort)
        has_security_dir = False
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            # IMAGE_DIRECTORY_ENTRY_SECURITY = 4
            if len(dd) > 4 and (dd[4].VirtualAddress or 0) != 0:
                has_security_dir = True
        except Exception:
            pass
        out = {
            'arch': arch,
            'compile_ts': ts,
            'sections': sections,
            'imports_top': imports_top,
            'exports_count': exports_count,
            'packer_flags': bool(packer_flags),
            'suspicious_imports': suspicious_imports[:10],
            'rwx_sections': rwx_sections[:5],
            'has_security_directory': has_security_dir,
        }
    except Exception as e:
        out['error'] = str(e)
    return out


def analyze_office(data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {'macros': {'present': False, 'iocs': []}}
    try:
        from oletools.olevba import VBA_Parser
        vb = VBA_Parser(io.BytesIO(data))
        info['macros']['present'] = vb.detect_vba_macros()
        if info['macros']['present']:
            iocs: List[str] = []
            try:
                for (filename, stream_path, vba_filename, vba_code) in vb.extract_all_macros():
                    if not vba_code:
                        continue
                    # Basic IOC extraction (URLs)
                    iocs.extend(re.findall(r'https?://[\w\.-/]+', vba_code)[:10])
            except Exception:
                pass
            info['macros']['iocs'] = list({s for s in iocs})[:20]
    except Exception as e:
        info['error'] = str(e)
    return info


def run_yara(data: bytes) -> List[str]:
    hits: List[str] = []
    try:
        import os
        import yara
        rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
        rule_files = {}
        if os.path.isdir(rules_dir):
            for fn in os.listdir(rules_dir):
                if fn.lower().endswith(('.yar', '.yara')):
                    rule_files[fn] = os.path.join(rules_dir, fn)
        if rule_files:
            rules = yara.compile(filepaths=rule_files)
            matches = rules.match(data=data)
            for m in matches:
                hits.append(m.rule)
    except Exception:
        pass
    return hits[:50]


@app.get('/healthz', response_class=PlainTextResponse)
def healthz():
    return 'ok'


@app.get('/metrics')
def metrics():
    output = generate_latest(registry)
    return PlainTextResponse(output.decode('utf-8'), media_type=CONTENT_TYPE_LATEST)


@app.post('/analyze')
async def analyze(file: UploadFile = File(...)):
    data = await file.read()
    sha = sha256_bytes(data)
    md5 = md5_bytes(data)
    # limit text size to avoid huge payload
    sample_text = ''
    try:
        sample_text = data[:100000].decode('utf-8', 'ignore')
    except Exception:
        sample_text = ''
    ftype = sniff_type(file.filename, data)
    h = heuristics(ftype, sample_text)
    details: Dict[str, Any] = {}
    if ftype == 'pe':
        details['pe'] = analyze_pe(data)
    if ftype == 'office':
        details['office'] = analyze_office(data)
    # YARA for all types (if rules exist)
    yh = run_yara(data)
    if yh:
        yara_hit_counter.inc(len(yh))
    jobs_processed.inc()
    return {
        'file': {
            'name': file.filename,
            'size': len(data),
            'type': ftype,
        },
        'hashes': {'sha256': sha, 'md5': md5},
        'heuristics': h,
        'details': details,
        'strings_sample': sample_text[:2000],
        'yara_hits': yh,
    }


@app.get('/schema')
def schema():
    try:
        import json, os
        p = os.path.join(os.path.dirname(__file__), 'schema_analyzer.json')
        with open(p, 'r', encoding='utf-8') as f:
            return JSONResponse(content=json.load(f))
    except Exception:
        return JSONResponse(status_code=500, content={"detail": "schema unavailable"})
