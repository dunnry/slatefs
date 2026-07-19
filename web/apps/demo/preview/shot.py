#!/usr/bin/env python3
"""Screenshot harness for the SlateFS demo redesign.

Renders the login screen and the app shell using the REAL styles.css from the
demo app, plus faithful mock shadow-DOM for the slatefs-* components. Mock
internals mirror the class names and styles in
packages/web-components/src/components.ts so host ::part() styling and the
--slatefs-* theming contract apply exactly as in production.

Usage: python3 preview/shot.py [login|files|versions|all]
"""
import pathlib
import sys

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSS = (ROOT / "src" / "styles.css").read_text()
OUT = ROOT / "preview" / "shots"
OUT.mkdir(exist_ok=True)

# Faithful copy of the shared base styles in packages/web-components/src/base.ts
# (dark fallbacks replaced by the host's --slatefs-* custom properties).
BASE_CSS = """
:host{display:block}
section{min-height:100%}
.toolbar{display:flex;align-items:center;gap:.5rem;min-height:3rem;padding:.55rem .75rem;border-bottom:1px solid var(--_border);flex-wrap:wrap}
h2{font-size:.95rem;font-weight:700;letter-spacing:-.01em;margin:0 auto 0 0}
button,.button{border:1px solid var(--_border);background:var(--_control-bg);color:var(--_control-text);border-radius:9px;min-height:2.25rem;padding:.4rem .75rem;cursor:pointer;font:inherit;box-shadow:0 1px 0 rgb(255 255 255/.04) inset;transition:border-color .16s ease,background .16s ease,box-shadow .16s ease,transform .12s ease}
button:hover{border-color:var(--_accent);background:color-mix(in srgb,var(--_control-bg) 82%,var(--_accent) 18%)}
button:active{transform:scale(.97)}
button.primary{background:linear-gradient(135deg,var(--_accent),color-mix(in srgb,var(--_accent) 72%,#5fe8c0 28%));border-color:transparent;color:var(--_accent-contrast);font-weight:680;box-shadow:0 0 0 1px color-mix(in srgb,var(--_accent) 40%,transparent),0 6px 18px -8px var(--_accent)}
button.primary:hover{box-shadow:0 0 0 1px color-mix(in srgb,var(--_accent) 55%,transparent),0 8px 22px -6px var(--_accent)}
input,select,textarea{border:1px solid var(--_border);border-radius:9px;padding:.45rem .6rem;min-height:2.25rem;background:var(--_control-bg);color:var(--_control-text);font:inherit;box-shadow:0 1px 0 rgb(255 255 255/.03) inset}
.muted{color:var(--_muted)}
.banner{margin:0;padding:.55rem .75rem;background:var(--slatefs-color-readonly);border-bottom:1px solid var(--_banner-border)}
.badge{display:inline-flex;align-items:center;border-radius:999px;background:var(--_subtle-bg);border:1px solid color-mix(in srgb,var(--_border) 80%,transparent);padding:.16rem .55rem;font-size:.76rem;font-weight:620;letter-spacing:.01em}
.quota-meter{flex:0 0 auto;inline-size:5.5rem;block-size:.4rem;border-radius:99px;background:color-mix(in srgb,var(--_subtle-bg) 80%,black 20%);overflow:hidden;box-shadow:0 0 0 1px color-mix(in srgb,var(--_border) 70%,transparent)}
.quota-meter>i{display:block;block-size:100%;border-radius:99px;background:linear-gradient(90deg,color-mix(in srgb,var(--_accent) 70%,#5fe8c0 30%),var(--_accent))}
.body{padding:.75rem}
.list{margin:0;padding:0;list-style:none}
.row{border-bottom:1px solid var(--_border);padding:.6rem .7rem;min-width:0}
.row:last-child{border-bottom:0}
.split{display:flex;gap:.5rem;align-items:center}
.grow{flex:1;min-width:0;overflow-wrap:anywhere}
"""


def shadow(inner_html, extra_css=""):
    return (
        '<template shadowrootmode="open"><style>'
        + BASE_CSS
        + extra_css
        + "</style>"
        + inner_html
        + "</template>"
    )


def volume_picker():
    inner = (
        '<header class="toolbar" part="toolbar"><label class="grow">'
        '<select part="select"><option>acme-demo-documents · local</option>'
        "<option>acme-archive · s3 · read-only</option></select></label>"
        '<button aria-label="Refresh volumes">&#8635;</button></header>'
        '<div class="body split" part="quota">'
        '<span class="badge" part="kind-badge">local</span>'
        '<span class="muted grow">1.2 GiB used of 5 GiB</span>'
        '<span class="quota-meter" part="quota-meter" role="meter" '
        'aria-valuemin="0" aria-valuemax="100" aria-valuenow="24" '
        'aria-label="Quota used"><i style="inline-size:24%"></i></span></div>'
    )
    return "<slatefs-volume-picker>" + shadow(inner) + "</slatefs-volume-picker>"


# Explorer styles copied from components.ts (SlateFsFileExplorer).
EXPLORER_CSS = """
.crumbs{padding:.55rem .75rem;border-bottom:1px solid var(--_border);display:flex;gap:.25rem;overflow:auto;align-items:center;color:var(--_muted);font-size:.85rem}
.crumbs button{border:0;padding:.2rem .35rem;background:transparent;color:var(--_accent);border-radius:6px;min-height:0}
.table{display:grid;grid-template-columns:minmax(13rem,3fr) minmax(7rem,1fr) 7rem minmax(9rem,1.3fr);max-height:32rem;overflow:auto}
.head,.entry{display:contents}
.cell{padding:.55rem .7rem;border-bottom:1px solid var(--_border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:background .14s ease}
.head .cell{position:sticky;top:0;background:var(--_subtle-bg);z-index:1;font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.08em;color:var(--_muted)}
.entry:hover .cell{background:color-mix(in srgb,var(--_selected-bg) 45%,transparent)}
.entry[aria-selected="true"] .cell{background:var(--_selected-bg)}
.entry[aria-selected="true"] .cell:first-child{box-shadow:inset 3px 0 color-mix(in srgb,var(--_accent) 75%,transparent)}
.name{font-weight:600;display:flex;align-items:center;gap:.55rem}
.entry-icon{flex:0 0 auto;width:1rem;height:1rem;color:var(--_muted)}
.entry[aria-selected="true"] .entry-icon,.entry:hover .entry-icon{color:var(--_accent)}
"""


def file_explorer():
    dir_icon = (
        '<svg class="entry-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>'
    )
    file_icon = (
        '<svg class="entry-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z"/>'
        '<path d="M14 3v4h4"/></svg>'
    )
    entries = [
        (dir_icon, "Contracts", "—", "directory", "Jul 14, 2:41 PM", "false"),
        (dir_icon, "Design", "—", "directory", "Jul 12, 9:15 AM", "false"),
        (file_icon, "Q3 roadmap.md", "24 KiB", "text/markdown", "Jul 15, 4:03 PM", "true"),
        (file_icon, "brand-guidelines.pdf", "2.4 MiB", "application/pdf", "Jul 11, 11:20 AM", "false"),
        (file_icon, "launch-plan.docx", "180 KiB", "document", "Jul 10, 5:47 PM", "false"),
        (file_icon, "budget-2026.xlsx", "96 KiB", "spreadsheet", "Jul 9, 1:12 PM", "false"),
        (file_icon, "hero-render.png", "4.1 MiB", "image/png", "Jul 8, 3:30 PM", "false"),
    ]
    rows = ""
    for icon, name, size, kind, mod, sel in entries:
        rows += (
            '<div class="entry" aria-selected="' + sel + '" part="row">'
            '<span class="cell name">' + icon + name + "</span>"
            '<span class="cell meta">' + size + "</span>"
            '<span class="cell meta">' + kind + "</span>"
            '<span class="cell meta">' + mod + "</span></div>"
        )
    inner = (
        '<header class="toolbar" part="toolbar"><h2>Files</h2>'
        '<input placeholder="Filter" value=""/><select><option>Sort: name</option></select>'
        '<button>New folder</button><button class="primary">Upload</button></header>'
        '<nav class="crumbs" part="breadcrumb" aria-label="Breadcrumb">'
        "<button>&#8962;</button><span>/</span><button>Documents</button></nav>"
        '<div class="table" role="grid" part="details-grid"><div class="head">'
        '<span class="cell">Name</span><span class="cell meta">Size</span>'
        '<span class="cell meta">Kind</span><span class="cell meta">Modified</span></div>'
        + rows + "</div>"
    )
    return "<slatefs-file-explorer>" + shadow(inner, EXPLORER_CSS) + "</slatefs-file-explorer>"


def file_preview():
    body = (
        "# Q3 Roadmap — SlateFS consumer launch\n\n"
        "## July\n"
        "- Ship tenant-isolated demo workspace\n"
        "- Snapshot browse → writable copy flow\n\n"
        "## August\n"
        "- Branch protection rules UI\n"
        "- Repository health dashboard"
    )
    inner = (
        '<header class="toolbar" part="toolbar"><h2 class="grow">Q3 roadmap.md</h2>'
        '<span class="badge">text/markdown</span><button>Download</button>'
        '<button class="primary">Save</button></header>'
        '<div class="body" part="preview"><pre part="text" style="margin:0;white-space:pre-wrap;'
        "font-family:ui-monospace,Menlo,monospace;font-size:.82rem;line-height:1.65\">"
        + body + "</pre></div>"
    )
    return (
        '<slatefs-file-preview id="file-preview" role="tabpanel">'
        + shadow(inner) + "</slatefs-file-preview>"
    )


def file_properties():
    inner = (
        '<header class="toolbar" part="toolbar"><h2>Details</h2></header>'
        '<div class="body" part="metadata">'
        '<dl style="display:grid;gap:.4rem;margin:0">'
        '<dt class="muted">Entry ID</dt><dd style="margin:0">ent_01J2…</dd>'
        '<dt class="muted">Size</dt><dd style="margin:0">24 KiB</dd></dl></div>'
    )
    return (
        '<slatefs-file-properties id="file-properties" role="tabpanel" hidden>'
        + shadow(inner) + "</slatefs-file-properties>"
    )


def version_status():
    def change_row(kind, path):
        return (
            '<li class="row" part="change-row"><label>'
            '<input type="checkbox" checked/>'
            '<span class="badge">' + kind + "</span> " + path + "</label></li>"
        )

    inner = (
        '<header class="toolbar" part="toolbar"><h2>Version status</h2>'
        '<span class="badge">main</span>'
        '<button class="primary">Save new version</button></header>'
        '<ul class="list">'
        + change_row("added", "Contracts/acme-msa-2026.pdf")
        + change_row("modified", "Q3 roadmap.md")
        + change_row("deleted", "Design/old-logo.sketch")
        + "</ul>"
    )
    return "<slatefs-version-status>" + shadow(inner) + "</slatefs-version-status>"


def version_history():
    def commit_row(msg, ref, author, when):
        return (
            '<li class="row split" part="commit-row"><div class="grow">'
            "<strong>" + msg + "</strong>"
            '<div part="parents" class="muted">' + ref + " · " + author + " · " + when + "</div>"
            "</div><button>Browse</button></li>"
        )

    inner = (
        '<header class="toolbar" part="toolbar"><h2>History</h2>'
        "<select><option>main</option></select></header>"
        '<ol class="list" part="history">'
        + commit_row("Snapshot before launch", "a1b2c3", "Alice", "Jul 15, 4:02 PM")
        + commit_row("Rename contracts folder", "d4e5f6", "Alice", "Jul 14, 2:40 PM")
        + commit_row("Import Q2 archive", "789abc", "Bob", "Jul 12, 9:00 AM")
        + "</ol>"
    )
    return "<slatefs-version-history>" + shadow(inner) + "</slatefs-version-history>"


def diff_viewer():
    def line(part, kind, path):
        return (
            '<li class="row" part="' + part + '"><button>'
            '<span class="badge">' + kind + "</span> " + path + "</button></li>"
        )

    inner = (
        '<header class="toolbar" part="toolbar"><h2>Compare</h2>'
        "<select><option>working tree</option></select>"
        '<span class="muted">&rarr;</span>'
        "<select><option>a1b2c3</option></select><button>Compare</button></header>"
        '<div part="diff" class="body"><p class="muted">'
        "3 changed paths. Binary and content patch rendering appears only when "
        "the server supplies bounded patch data.</p>"
        '<ul class="list">'
        + line("addition", "add", "Contracts/acme-msa-2026.pdf")
        + line("line", "modify", "Q3 roadmap.md")
        + line("deletion", "delete", "Design/old-logo.sketch")
        + "</ul></div>"
    )
    return "<slatefs-diff-viewer>" + shadow(inner) + "</slatefs-diff-viewer>"


def snapshot_manager():
    def snap_row(name, when):
        return (
            '<li class="row split" part="snapshot-row"><div class="grow">'
            "<strong>" + name + "</strong>"
            '<div class="muted">' + when + "</div></div>"
            "<button>Browse</button><button>Create writable copy</button></li>"
        )

    inner = (
        '<header class="toolbar" part="toolbar"><h2>Snapshots</h2>'
        "<button>Create snapshot</button></header>"
        '<ul class="list" part="snapshot-list">'
        + snap_row("pre-launch-2026-07-15", "Jul 15, 4:00 PM")
        + snap_row("daily-2026-07-14", "Jul 14, 12:00 AM")
        + "</ul>"
    )
    return "<slatefs-snapshot-manager>" + shadow(inner) + "</slatefs-snapshot-manager>"


BRANCH_CSS = """
.branch-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(18rem,100%),1fr));gap:.75rem;min-width:0;max-width:100%;padding:.75rem}
.branch-row{display:flex;flex-wrap:wrap;align-items:start;gap:.5rem;max-width:100%;border:1px solid var(--_border);border-radius:10px;background:var(--slatefs-color-control)}
.branch-row.target{border-color:var(--_accent);box-shadow:inset 0 0 0 1px var(--_accent)}
.branch-row.source{background:var(--slatefs-color-source);border-color:var(--slatefs-color-source-border)}
.branch-summary{flex:1 1 16rem;min-width:0;max-width:100%;overflow:hidden;text-align:start;white-space:normal}
.branch-name{overflow-wrap:anywhere;word-break:break-word}
.branch-actions{display:flex;flex:0 0 auto;flex-wrap:wrap;gap:.5rem}
"""


def branch_manager():
    def branch_row(name, commit, cls, badges):
        return (
            '<li class="row branch-row ' + cls + '" part="branch-row">'
            '<button class="branch-summary" part="branch-summary">'
            '<strong class="branch-name" part="branch-name">' + name + "</strong>"
            + badges
            + '<div class="muted">' + commit + "</div></button>"
            '<div class="branch-actions" part="branch-actions">'
            "<button>Use as source</button><button>Browse</button></div></li>"
        )

    inner = (
        '<header class="toolbar" part="toolbar"><h2>Branches</h2>'
        "<button>New branch</button></header>"
        '<p class="banner">Branches are publish targets for history. '
        "They are not checked-out working trees.</p>"
        '<ul class="list branch-list" part="branch-list">'
        + branch_row("main", "a1b2c3d4e5f6", "target", '<span class="badge">Target</span>')
        + branch_row("feature/launch-copy", "789abcdef0", "", "")
        + "</ul>"
    )
    return "<slatefs-branch-manager>" + shadow(inner, BRANCH_CSS) + "</slatefs-branch-manager>"


REPO_CSS = """
pre{background:var(--_subtle-bg);border:1px solid var(--_border);border-radius:8px;padding:.6rem;overflow:auto;font-size:.78rem;line-height:1.5}
h3{margin:.9rem 0 .4rem;font-size:.9rem}
"""


def repository_tools():
    stats = '{\n  "objects": 1284,\n  "commits": 42,\n  "storage": "1.2 GiB",\n  "last_verified": "2026-07-15T16:05:00Z"\n}'
    inner = (
        '<header class="toolbar" part="toolbar"><h2>Repository health</h2>'
        "<button>Verify</button></header>"
        '<div class="body"><div part="stats"><h3>Statistics</h3>'
        "<pre>" + stats + "</pre></div>"
        '<p class="muted">Safe consumer tools only. Bundle transfer, native '
        "sync, retention changes, garbage collection, purge, leases, and fleet "
        "controls are intentionally unavailable.</p></div>"
    )
    return "<slatefs-repository-tools>" + shadow(inner, REPO_CSS) + "</slatefs-repository-tools>"


LOGIN = (
    '<main class="login"><section class="login-card"><div class="brand-mark">S</div>'
    '<p class="eyebrow">SlateFS Consumer Demo</p><h1>Your files, with a memory.</h1>'
    '<p class="lede">Browse a familiar filesystem, then step back through snapshots '
    "and intentional versions without leaving your workspace.</p>"
    "<form><fieldset><legend>Choose a demo workspace</legend>"
    '<button class="account" type="button" value="alice">'
    '<span class="avatar alice">A</span><span><strong>Alice</strong>'
    "<small>Acme workspace · password: slatefs</small></span>"
    '<span class="go" aria-hidden="true">&rarr;</span></button>'
    '<button class="account" type="button" value="bob">'
    '<span class="avatar bob">B</span><span><strong>Bob</strong>'
    "<small>Globex workspace · password: slatefs</small></span>"
    '<span class="go" aria-hidden="true">&rarr;</span></button>'
    "</fieldset>"
    '<p role="status" aria-live="polite"></p></form>'
    '<p class="privacy">Each account is locked to its own tenant. No tenant selector '
    "or SlateFS token reaches this browser.</p></section>"
    '<aside class="login-art" aria-hidden="true"><div class="strata">'
    "<i></i><i></i><i></i><i></i></div>"
    "<p>Live files<br><span>Snapshots</span><br><span>Version history</span></p>"
    "</aside></main>"
)


def icon(paths):
    return (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" '
        'aria-hidden="true">' + paths + "</svg>"
    )


ICONS = {
    "files": icon('<path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>'),
    "versions": icon('<circle cx="6" cy="6" r="2.4"/><circle cx="6" cy="18" r="2.4"/><circle cx="18" cy="12" r="2.4"/><path d="M6 8.4v7.2"/><path d="M8 7l7.7 4"/>'),
    "snapshots": icon('<circle cx="12" cy="12" r="8.2"/><circle cx="12" cy="12" r="3.4"/>'),
    "branches": icon('<circle cx="6" cy="5.5" r="2.2"/><circle cx="6" cy="18.5" r="2.2"/><circle cx="18" cy="7.5" r="2.2"/><path d="M6 7.7v8.6"/><path d="M18 9.7c0 4.5-6 2.7-9.4 6.1"/>'),
    "health": icon('<path d="M3.5 12h4l2-5.5 4.5 11 2.5-5.5h3.5"/>'),
}


def shell_page(active, drawer=False):
    tab = (
        '<button class="tab" role="tab" data-tab="{t}" aria-selected="{sel}">'
        "<b>{icon}</b>{label}</button>"
    )
    rail = (
        tab.format(t="files", sel=str(active == "files").lower(), icon=ICONS["files"], label="Files")
        + tab.format(t="versions", sel=str(active == "versions").lower(), icon=ICONS["versions"], label="Versions")
        + tab.format(t="snapshots", sel="false", icon=ICONS["snapshots"], label="Snapshots")
        + tab.format(t="branches", sel="false", icon=ICONS["branches"], label="Branches")
        + tab.format(t="health", sel="false", icon=ICONS["health"], label="Health")
    )
    drawer_html = ""
    if drawer:
        drawer_html = (
            '<aside class="operation-drawer" aria-label="Recent file operations">'
            "<header><strong>Operations</strong><span>1 active</span>"
            "<button>Clear completed</button></header>"
            '<ul aria-live="polite">'
            "<li><span>upload: running &mdash; hero-render.png</span>"
            '<progress max="1" value="0.62"></progress>'
            '<span class="operation-actions"><button>Cancel</button>'
            "<button>Dismiss</button></span></li>"
            "<li><span>commit: success &mdash; Snapshot before launch</span>"
            '<progress max="1" value="1"></progress>'
            '<span class="operation-actions"><button>Dismiss</button></span></li>'
            "</ul></aside>"
        )
    eyebrow = "LIVE WORKSPACE" if active == "files" else "VERSIONS"
    title = "Files" if active == "files" else "Version history"
    files_active = "active" if active == "files" else ""
    versions_active = "active" if active == "versions" else ""

    return (
        '<div class="app">'
        '<header class="topbar">'
        '<a class="brand" href="/" aria-label="SlateFS home"><span>S</span> SlateFS</a>'
        '<div class="tenant"><span class="tenant-dot"></span>'
        "<span><strong>Alice</strong><small>Acme workspace</small></span></div>"
        '<button id="switch">Switch account</button></header>'
        '<nav class="rail" aria-label="Workspace" role="tablist">'
        + rail
        + '<div class="rail-foot"><span>Tenant isolated</span>'
        '<button id="logout">Sign out</button></div></nav>'
        '<main class="workspace">'
        '<p id="host-message" class="host-message" role="status" aria-live="polite" hidden></p>'
        '<div class="workspace-head"><div>'
        '<p class="eyebrow">' + eyebrow + "</p><h1>" + title + "</h1></div>"
        '<div class="workspace-actions">'
        '<button id="return-live" type="button" hidden>Return to live files</button>'
        + volume_picker()
        + "</div></div>"
        '<section id="panel-files" role="tabpanel" class="panel ' + files_active + '" data-panel="files">'
        + file_explorer()
        + '<aside class="inspector">'
        '<div class="inspector-tabs" role="tablist" aria-label="File inspector">'
        '<button role="tab" data-inspect="preview" aria-selected="true">Preview</button>'
        '<button role="tab" data-inspect="details">Details</button></div>'
        + file_preview()
        + file_properties()
        + "</aside></section>"
        '<section id="panel-versions" role="tabpanel" class="panel ' + versions_active + '" data-panel="versions">'
        + version_status()
        + version_history()
        + diff_viewer()
        + "<slatefs-restore-dialog></slatefs-restore-dialog>"
        + "</section>"
        '<section id="panel-snapshots" role="tabpanel" class="panel" data-panel="snapshots">'
        + snapshot_manager()
        + "</section>"
        '<section id="panel-branches" role="tabpanel" class="panel" data-panel="branches">'
        + branch_manager()
        + "</section>"
        '<section id="panel-health" role="tabpanel" class="panel" data-panel="health">'
        + repository_tools()
        + "</section>"
        "</main></div>"
        + drawer_html
    )


def page(body):
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<style>" + CSS + "</style></head><body>"
        '<div id="app">' + body + "</div></body></html>"
    )


PAGES = {
    "login": lambda: page(LOGIN),
    "files": lambda: page(shell_page("files", drawer=True)),
    "versions": lambda: page(shell_page("versions")),
}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    names = list(PAGES) if which == "all" else [which]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name in names:
            pg = browser.new_page(
                viewport={"width": 1680, "height": 1050}, device_scale_factor=2
            )
            pg.set_content(PAGES[name]())
            pg.wait_for_timeout(350)
            out = OUT / (name + ".png")
            pg.screenshot(path=str(out), full_page=False)
            pg.close()
            print("wrote " + str(out))
        browser.close()


if __name__ == "__main__":
    main()
