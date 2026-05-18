from __future__ import annotations

import html


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def build_html_report(result: dict) -> str:
    findings = result["findings"]
    rows = "\n".join(
        f"""
        <article class="finding severity-{_esc(finding['severity'])}">
          <div class="severity">{_esc(finding['severity']).upper()}</div>
          <h2>{_esc(finding['title'])}</h2>
          <p><strong>Evidence:</strong> {_esc(finding['evidence'])}</p>
          <p><strong>Recommendation:</strong> {_esc(finding['recommendation'])}</p>
        </article>
        """
        for finding in findings
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Civic Sentinel Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #18202b;
      --muted: #586373;
      --line: #d9dee7;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --critical: #9d1c2f;
      --high: #c44228;
      --medium: #9b6a00;
      --low: #27636f;
      --info: #56606f;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      padding: 28px clamp(18px, 5vw, 56px);
    }}
    main {{
      width: min(1040px, calc(100% - 36px));
      margin: 28px auto 56px;
    }}
    h1, h2, p {{ margin-top: 0; }}
    h1 {{ margin-bottom: 6px; font-size: clamp(1.7rem, 4vw, 2.4rem); }}
    .meta {{ color: var(--muted); margin-bottom: 18px; }}
    .score {{
      display: inline-flex;
      align-items: baseline;
      gap: 10px;
      padding: 12px 16px;
      border: 1px solid var(--line);
      background: var(--panel);
      font-weight: 700;
    }}
    .score strong {{ font-size: 2rem; }}
    .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-left-width: 6px;
      padding: 18px;
      margin: 14px 0;
    }}
    .finding h2 {{ font-size: 1.05rem; margin-bottom: 10px; }}
    .finding p {{ margin-bottom: 8px; }}
    .severity {{
      font-size: .76rem;
      font-weight: 800;
      color: var(--muted);
      letter-spacing: 0;
      margin-bottom: 7px;
    }}
    .severity-critical {{ border-left-color: var(--critical); }}
    .severity-high {{ border-left-color: var(--high); }}
    .severity-medium {{ border-left-color: var(--medium); }}
    .severity-low {{ border-left-color: var(--low); }}
    .severity-info {{ border-left-color: var(--info); }}
  </style>
</head>
<body>
  <header>
    <h1>Civic Sentinel Report</h1>
    <p class="meta">{_esc(result['target']['normalized_url'])} · generated {_esc(result['generated_at'])}</p>
    <div class="score"><strong>{_esc(result['risk']['score'])}</strong><span>/100 · {_esc(result['risk']['level'])}</span></div>
  </header>
  <main>
    {rows or "<p>No findings were produced.</p>"}
  </main>
</body>
</html>
"""

