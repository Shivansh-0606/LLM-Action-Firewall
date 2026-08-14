"""
Deterministic post-generation action firewall.
No LLM. No suspicious-phrase matching. Pure schema/scope/approval/HTML-structure checks.
"""
import json
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ASSIGNED_TENANT = "tenant-d1tkehz"
ALLOWED_EMAIL_DOMAIN = "notify-plyqwn5.example"
ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}

REASONS = [
    "ALLOW", "INVALID_SCHEMA", "TOOL_NOT_ALLOWED", "TENANT_SCOPE",
    "EGRESS_DENIED", "APPROVAL_REQUIRED", "UNSAFE_OUTPUT",
]


class UnsafeHTMLParser(HTMLParser):
    """Structural HTML check: banned tags, inline event-handler attrs,
    javascript: scheme in url-bearing attrs. Not string/phrase matching —
    operates on parsed tag/attribute structure."""

    BANNED_TAGS = {"script", "iframe", "object", "embed"}
    URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        self._check(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._check(tag, attrs)

    def _check(self, tag, attrs):
        tag = tag.lower()
        if tag in self.BANNED_TAGS:
            self.unsafe = True
            return
        for name, value in attrs:
            name_l = (name or "").lower()
            if name_l.startswith("on"):  # inline event handler attribute
                self.unsafe = True
                return
            if name_l in self.URL_ATTRS and value:
                v = value.strip().lower()
                # strip control-ish chars a browser would ignore when sniffing scheme
                v_clean = "".join(ch for ch in v if ch not in "\t\n\r")
                if v_clean.startswith("javascript:"):
                    self.unsafe = True
                    return


def is_unsafe_html(html: str) -> bool:
    parser = UnsafeHTMLParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # Malformed markup we can't safely parse -> treat as unsafe.
        return True
    return parser.unsafe


def block(reason):
    return {"decision": "block", "reason": reason}


def allow():
    return {"decision": "allow", "reason": "ALLOW"}


def check_action(payload):
    # ---- 1. Top-level schema ----
    if not isinstance(payload, dict):
        return block("INVALID_SCHEMA")

    allowed_top_keys = {"provenance", "humanApproved", "untrustedContent", "action"}
    required_top_keys = {"provenance", "humanApproved", "action"}
    keys = set(payload.keys())
    if not required_top_keys.issubset(keys) or not keys.issubset(allowed_top_keys):
        return block("INVALID_SCHEMA")

    provenance = payload.get("provenance")
    humanApproved = payload.get("humanApproved")
    untrustedContent = payload.get("untrustedContent", None)
    action = payload.get("action")

    if provenance not in ("trusted", "untrusted"):
        return block("INVALID_SCHEMA")
    if not isinstance(humanApproved, bool):
        return block("INVALID_SCHEMA")
    if untrustedContent is not None and not isinstance(untrustedContent, str):
        return block("INVALID_SCHEMA")
    if not isinstance(action, dict):
        return block("INVALID_SCHEMA")
    if set(action.keys()) != {"tool", "args"}:
        return block("INVALID_SCHEMA")

    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(tool, str) or not isinstance(args, dict):
        return block("INVALID_SCHEMA")

    # ---- 2. Tool allowlist ----
    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # ---- 3. Selected tool's argument schema ----
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return block("INVALID_SCHEMA")
        query = args["query"]
        if not isinstance(query, str) or not (1 <= len(query) <= 200):
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return block("INVALID_SCHEMA")
        tenantId, recordId = args["tenantId"], args["recordId"]
        if not isinstance(tenantId, str) or not isinstance(recordId, str):
            return block("INVALID_SCHEMA")
        if len(tenantId) == 0 or len(recordId) == 0:
            return block("INVALID_SCHEMA")

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return block("INVALID_SCHEMA")
        to, subject, body = args["to"], args["subject"], args["body"]
        if not all(isinstance(x, str) for x in (to, subject, body)):
            return block("INVALID_SCHEMA")
        if to.count("@") != 1:
            return block("INVALID_SCHEMA")
        local, _, domain = to.partition("@")
        if not local or not domain:
            return block("INVALID_SCHEMA")

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return block("INVALID_SCHEMA")
        if not isinstance(args["html"], str):
            return block("INVALID_SCHEMA")

    # ---- 4. Tenant scope ----
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # ---- 5. Exact email domain ----
    if tool == "send_email":
        domain = args["to"].split("@", 1)[1]
        if domain != ALLOWED_EMAIL_DOMAIN:
            return block("EGRESS_DENIED")

    # ---- 6. Human approval ----
    if tool == "send_email":
        if humanApproved is not True:
            return block("APPROVAL_REQUIRED")

    # ---- 7. HTML safety ----
    if tool == "render_html":
        if is_unsafe_html(args["html"]):
            return block("UNSAFE_OUTPUT")

    return allow()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        pass  # quiet

    def do_POST(self):
        if self.path != "/action-firewall":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            result = block("INVALID_SCHEMA")
        else:
            try:
                result = check_action(payload)
            except Exception:
                result = block("INVALID_SCHEMA")
        body = json.dumps(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port=8765):
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"listening on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    import os, sys
    port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else 8765))
    serve(port)
