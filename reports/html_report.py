import datetime
import html
from config.settings import Settings


class HTMLReport:
    SEV_COLORS = {
        "CRITICAL": "#ff3333",
        "HIGH":     "#ff7700",
        "MEDIUM":   "#f0c040",
        "LOW":      "#3399ff",
        "INFO":     "#888888",
    }
    SEV_BG = {
        "CRITICAL": "rgba(255,51,51,0.08)",
        "HIGH":     "rgba(255,119,0,0.07)",
        "MEDIUM":   "rgba(240,192,64,0.07)",
        "LOW":      "rgba(51,153,255,0.06)",
        "INFO":     "rgba(136,136,136,0.04)",
    }

    def __init__(self, findings, meta=None):
        self.findings = findings
        self.meta     = meta or {}

    def _counts(self):
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            if sev in c:
                c[sev] += 1
        return c

    def _sev_badge(self, sev):
        color = self.SEV_COLORS.get(sev, "#888")
        return (
            f'<span style="color:{color};font-weight:700;font-size:.75rem;'
            f'letter-spacing:.08em;text-transform:uppercase;'
            f'border:1px solid {color};border-radius:3px;'
            f'padding:2px 7px">{html.escape(sev)}</span>'
        )

    def _finding_rows(self):
        rows = ""
        for f in self.findings:
            sev  = f.get("severity", "INFO").upper()
            bg   = self.SEV_BG.get(sev, "")
            rows += f"""
        <tr style="background:{bg}">
          <td style="white-space:nowrap">{self._sev_badge(sev)}</td>
          <td style="color:#666;font-size:.78rem">{html.escape(f.get('module',''))}</td>
          <td style="font-weight:500">{html.escape(f.get('title',''))}</td>
          <td style="color:#aaa;font-size:.82rem">{html.escape(f.get('description','')[:180])}</td>
          <td style="color:#5af;font-size:.78rem">{html.escape(f.get('recommendation','')[:140])}</td>
        </tr>"""
        return rows

    def build(self):
        now     = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        target  = self.meta.get("host", "")
        ip      = self.meta.get("ip", "")
        profile = self.meta.get("profile", "default")
        c       = self._counts()
        total   = sum(c.values())

        stat_boxes = ""
        for label, key, color in [
            ("CRITICAL", "CRITICAL", "#ff3333"),
            ("HIGH",     "HIGH",     "#ff7700"),
            ("MEDIUM",   "MEDIUM",   "#f0c040"),
            ("LOW",      "LOW",      "#3399ff"),
            ("INFO",     "INFO",     "#888888"),
        ]:
            stat_boxes += f"""
        <div class="stat-box">
          <div class="stat-label">{label}</div>
          <div class="stat-val" style="color:{color}">{c[key]}</div>
        </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhantomEye — {html.escape(target)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  :root{{
    --bg:#0a0a0f;--surface:#0f0f18;--border:#1a1a2a;
    --text:#d0d0e0;--dim:#555;--accent:#7733ff;
  }}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:14px;line-height:1.6}}
  a{{color:#5af;text-decoration:none}}
  .wrap{{max-width:1280px;margin:0 auto;padding:40px 24px}}

  /* Header */
  .header{{margin-bottom:36px;border-bottom:1px solid var(--border);padding-bottom:28px}}
  .logo{{font-size:2.2rem;font-weight:800;letter-spacing:.15em;color:#fff;
         text-shadow:0 0 24px #7733ff88}}
  .logo span{{color:var(--accent)}}
  .tagline{{color:var(--dim);font-size:.82rem;letter-spacing:.12em;text-transform:uppercase;
             margin-top:4px}}

  /* Meta grid */
  .meta-grid{{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}}
  .meta-item{{background:var(--surface);border:1px solid var(--border);
               border-radius:6px;padding:10px 18px;min-width:140px}}
  .meta-item .lbl{{color:var(--dim);font-size:.68rem;text-transform:uppercase;
                    letter-spacing:.1em}}
  .meta-item .val{{font-size:.95rem;font-weight:600;margin-top:2px;
                    font-family:monospace;color:#e0e0f0}}

  /* Stat boxes */
  .stats{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:32px}}
  .stat-box{{background:var(--surface);border:1px solid var(--border);
              border-radius:6px;padding:14px 22px;text-align:center;min-width:100px}}
  .stat-label{{font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}}
  .stat-val{{font-size:2rem;font-weight:800;margin-top:4px;font-family:monospace}}

  /* Progress bar */
  .sev-bar{{display:flex;height:5px;border-radius:3px;overflow:hidden;margin-bottom:32px;
             background:var(--border)}}
  .sev-bar div{{transition:width .4s}}

  /* Table */
  .findings-table{{width:100%;border-collapse:collapse;background:var(--surface);
                    border-radius:8px;overflow:hidden;border:1px solid var(--border)}}
  .findings-table th{{background:#0d0d1a;padding:10px 14px;text-align:left;
                       font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;
                       color:var(--dim);border-bottom:1px solid var(--border)}}
  .findings-table td{{padding:9px 14px;border-bottom:1px solid var(--border);
                       vertical-align:top}}
  .findings-table tr:hover td{{background:rgba(119,51,255,.04)}}
  .findings-table tr:last-child td{{border-bottom:none}}

  /* Section title */
  .section-title{{font-size:1rem;font-weight:700;letter-spacing:.06em;
                   text-transform:uppercase;color:#9966ff;margin-bottom:16px;
                   border-left:3px solid #7733ff;padding-left:12px}}

  /* Footer */
  footer{{margin-top:48px;text-align:center;color:var(--dim);font-size:.72rem;
           letter-spacing:.08em;border-top:1px solid var(--border);padding-top:20px}}

  /* No findings */
  .empty{{text-align:center;padding:48px;color:var(--dim);font-size:.9rem}}

  @media(max-width:700px){{
    .stats{{flex-direction:column}}
    .meta-grid{{flex-direction:column}}
    .findings-table{{font-size:.78rem}}
  }}
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="logo">PHANTOM<span>EYE</span></div>
    <div class="tagline">Hybrid Vulnerability Assessment Framework &mdash; v{Settings.VERSION} &mdash; {Settings.AUTHOR}</div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><div class="lbl">Target</div><div class="val">{html.escape(target)}</div></div>
    <div class="meta-item"><div class="lbl">IP</div><div class="val">{html.escape(ip)}</div></div>
    <div class="meta-item"><div class="lbl">Profile</div><div class="val">{html.escape(profile)}</div></div>
    <div class="meta-item"><div class="lbl">Generated</div><div class="val" style="font-size:.78rem">{html.escape(now)}</div></div>
    <div class="meta-item"><div class="lbl">Total Findings</div><div class="val">{total}</div></div>
  </div>

  <div class="stats">{stat_boxes}
  </div>

  <div class="sev-bar">
    <div style="width:{(c['CRITICAL']/max(total,1))*100:.1f}%;background:#ff3333"></div>
    <div style="width:{(c['HIGH']/max(total,1))*100:.1f}%;background:#ff7700"></div>
    <div style="width:{(c['MEDIUM']/max(total,1))*100:.1f}%;background:#f0c040"></div>
    <div style="width:{(c['LOW']/max(total,1))*100:.1f}%;background:#3399ff"></div>
    <div style="width:{(c['INFO']/max(total,1))*100:.1f}%;background:#555"></div>
  </div>

  <div class="section-title">Findings</div>

  {'<div class="empty">No findings recorded.</div>' if not self.findings else f"""
  <table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Module</th>
        <th>Title</th>
        <th>Description</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{self._finding_rows()}
    </tbody>
  </table>"""}

  <footer>
    {html.escape(Settings.TOOL_NAME)} v{Settings.VERSION} &mdash;
    {html.escape(Settings.AUTHOR)} &mdash; {html.escape(now)}
    &mdash; For authorised security assessment only.
  </footer>

</div>
</body>
</html>"""

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.build())
