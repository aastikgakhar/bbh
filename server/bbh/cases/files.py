"""File-handling generators: upload, path_traversal.

Uploads are tiny and harmless (a text/SVG/GIF-polyglot marker, never an
executable or server-side script). Path traversal proves itself with
normalisation differentials and the application's OWN public files only, never
a system file (no /etc/passwd, no win.ini).
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


@_gen("upload")
def gen_upload(ctx: Ctx) -> list[TestCase]:
    field = ctx.input_name or "file"
    served = ctx.extra.get("served_path_template")  # e.g. "/uploads/{name}"
    cases: list[TestCase] = []
    ctrl_name = f"{ctx.token('c')}.png"
    cases.append(TestCase(case_no=0, technique="upload.control.allowed", payload=ctrl_name,
                          mutation=[{"op": "set_input", "value": ctrl_name}], is_control=True,
                          positive={"type": "status_in", "values": [200, 201, 204]},
                          negative="a normal image upload is rejected, so the tooling or endpoint is wrong",
                          description="control: a legitimate image uploads successfully"))
    n = 1
    tok = ctx.token("m")
    # family = the bypass dimension (extension / mime / magic / disposition / name)
    bypasses = [
        ("ext", "html", f"{ctx.token(1)}.html"),
        ("ext", "svg", f"{ctx.token(2)}.svg"),
        ("ext", "double", f"{ctx.token(3)}.png.html"),
        ("ext", "trailing_dot", f"{ctx.token(4)}.html."),
        ("ext", "case", f"{ctx.token(5)}.HtMl"),
        ("name", "null_sep", f"{ctx.token(6)}.html%00.png"),
        ("name", "space", f"{ctx.token(7)}.html "),
    ]
    for family, variant, name in bypasses:
        cases.append(TestCase(case_no=n, technique=f"upload.{family}.{variant}", payload=name,
                              mutation=[{"op": "set_input", "value": name}],
                              positive={"type": "status_in", "values": [200, 201, 204]},
                              negative=f"the {family}/{variant} filename is rejected by the upload filter",
                              rung="extension_bypass", description=f"upload extension/name bypass: {variant}"))
        n += 1
    # magic-byte / content families (multipart body carries a marker + a dangerous content type)
    for family, variant, name, body, ctype in [
        ("magic", "gif_polyglot", f"{ctx.token(8)}.html", f"GIF89a<script>document.title='{tok}'</script>", "image/gif"),
        ("mime", "html_as_png", f"{ctx.token(9)}.png", f"<script>document.title='{tok}'</script>", "image/png"),
        ("svg", "script", f"{ctx.token(10)}.svg", f"<svg xmlns='http://www.w3.org/2000/svg' onload=\"document.title='{tok}'\"><text>{tok}</text></svg>", "image/svg+xml"),
    ]:
        cases.append(TestCase(case_no=n, technique=f"upload.{family}.{variant}", payload=name,
                              mutation=[{"op": "set_input", "value": name},
                                        {"op": "set_param", "location": "multipart", "name": field, "value": body}],
                              positive={"type": "status_in", "values": [200, 201, 204]},
                              negative=f"the {variant} content is rejected",
                              rung="extension_bypass", description=f"upload content/magic bypass: {variant}"))
        n += 1
    # served-inline + execution (only when the serving path is known)
    if served:
        read_path = served.replace("{name}", "{{UPLOADED_NAME}}")
        cases.append(TestCase(case_no=n, technique="upload.serve.inline_html", payload="serve uploaded html",
                              mutation=[{"op": "set_input", "value": f"{ctx.token('s')}.html"},
                                        {"op": "set_param", "location": "multipart", "name": field, "value": f"<script>document.title='{tok}'</script>"}],
                              route="browser", positive={"type": "browser_marker", "token": tok},
                              negative="the uploaded HTML is served as an attachment or on a sandboxed origin, so it does not execute",
                              rung="served_inline_same_origin",
                              extra={"browser": {"open": "path", "path": read_path, "wait_ms": 1500}, "needs_uploaded_name": True},
                              description="upload served inline on the primary origin and executes"))
        n += 1
    else:
        cases.append(TestCase(case_no=n, technique="upload.serve.disposition", payload="inspect Content-Disposition",
                              mutation=[{"op": "set_input", "value": f"{ctx.token('s')}.svg"}],
                              positive={"type": "manual", "describe": "fetch the uploaded file's URL and check whether it is served inline on the primary origin (Content-Type, Content-Disposition, and the serving host)"},
                              negative="the serving origin and disposition are not identified",
                              rung="served_inline_same_origin", description="identify where uploads are served and how"))
        n += 1
    return cases


@_gen("path_traversal")
def gen_path_traversal(ctx: Ctx) -> list[TestCase]:
    base = ctx.sample_value or "report.pdf"
    public = ctx.extra.get("known_public_files") or ["robots.txt", "favicon.ico", "static/app.js"]
    target = public[0]
    marker = ctx.extra.get("public_file_marker")  # a string known to be in that file
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="path_traversal.control.plain", payload=base,
                          mutation=[{"op": "set_input", "value": base}], is_control=True,
                          positive={"type": "status_in", "values": [200]},
                          negative="the normal filename does not fetch its file, so the tooling is wrong",
                          description="control: the normal file name is served"))
    n = 1
    # normalisation-differential family: ./x and sub/../x must equal x (proves the path is resolved)
    for family, variant, payload in [
        ("norm", "dot_slash", f"./{base}"),
        ("norm", "sub_dotdot", f"sub/../{base}"),
        ("norm", "double_slash", f".//{base}"),
    ]:
        cases.append(TestCase(case_no=n, technique=f"path_traversal.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "same_as_case", "a": "this", "case": 0, "max_len_diff": 8},
                              negative=f"the {variant} form is not normalised to the base file, so the path is opaque",
                              rung="normalisation_differential", description=f"path normalisation differential: {variant}"))
        n += 1
    # traversal to the app's own public files, various encodings
    def pos(variant):
        if marker:
            return {"type": "body_contains", "value": marker}
        return {"type": "all", "of": [{"type": "status_in", "values": [200]},
                                     {"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 8}}]}
    enc = [
        ("depth", "dotdot_1", f"../{target}"),
        ("depth", "dotdot_2", f"../../{target}"),
        ("depth", "dotdot_3", f"../../../{target}"),
        ("urlenc", "single", f"..%2f..%2f{target}"),
        ("urlenc", "double", f"..%252f..%252f{target}"),
        ("altsep", "backslash", f"..\\..\\{target}"),
        ("unicode", "overlong", f"..%c0%af..%c0%af{target}"),
        ("altsep", "dot_semi", f"..;/..;/{target}"),
    ]
    for family, variant, payload in enc:
        cases.append(TestCase(case_no=n, technique=f"path_traversal.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive=pos(variant), negative=f"the {variant} traversal does not reach {target}",
                              rung="traversal_reads_app_file", description=f"path traversal to an app-owned file: {variant}"))
        n += 1
    return cases
