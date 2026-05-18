"""Print-friendly HTML report for a case.

Served at GET /report/<case_id>. The user clicks browser Print > Save as PDF
to produce a shareable file. Zero server-side dependencies; the browser
handles rendering, including any inline SVGs we embed.
"""
import html
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import case_manager


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with path.open("r") as f:
            return json.load(f)
    except Exception:
        return None


def _esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))


def _render_findings(rcs: List[Dict[str, Any]]) -> str:
    if not rcs:
        return "<p class='muted'>No root causes identified.</p>"
    out = []
    for rc in rcs:
        conf = _esc(rc.get("confidence_level", "?"))
        pct = _esc(rc.get("confidence_pct", "?"))
        out.append(
            f"<div class='finding'>"
            f"<div class='finding-h'><strong>{_esc(rc.get('issue', 'Root cause'))}</strong>"
            f" <span class='badge'>{conf} · {pct}%</span></div>"
            f"<div>{_esc(rc.get('description', ''))}</div>"
            f"<div class='muted'><em>Impact:</em> {_esc(rc.get('impact', '—'))}</div>"
            f"<div class='muted'><em>Confidence rationale:</em> {_esc(rc.get('confidence_justification', '—'))}</div>"
            + (_render_evidence(rc.get('evidence_refs') or []))
            + "</div>"
        )
    return "\n".join(out)


def _render_evidence(items: List[str]) -> str:
    if not items:
        return ""
    lis = "".join(f"<li>{_esc(x)}</li>" for x in items)
    return f"<div class='muted'><em>Evidence:</em><ul>{lis}</ul></div>"


def _render_radio_findings(rfs: List[Dict[str, Any]]) -> str:
    if not rfs:
        return "<p class='muted'>No radio findings.</p>"
    out = []
    for rf in rfs:
        out.append(
            f"<div class='finding'>"
            f"<div class='finding-h'><strong>{_esc(rf.get('finding_type'))}</strong>"
            f" <span class='badge'>{_esc(rf.get('confidence_level', '?'))} · {_esc(rf.get('confidence_pct', '?'))}%</span>"
            f" <span class='muted small'>{_esc(rf.get('source', ''))}</span></div>"
            f"<div>{_esc(rf.get('description', ''))}</div>"
            + _render_evidence(rf.get('evidence') or [])
            + "</div>"
        )
    return "\n".join(out)


def _render_kpis(summary: Dict[str, Any]) -> str:
    kpis = (summary or {}).get("kpi_statistics") or {}
    if not kpis:
        return "<p class='muted'>No KPI statistics available.</p>"
    rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v.get('min'))}</td>"
        f"<td>{_esc(v.get('avg'))}</td><td>{_esc(v.get('max'))}</td>"
        f"<td>{_esc(v.get('unit'))}</td></tr>"
        for k, v in kpis.items()
    )
    return f"""<table class='kpi'>
      <thead><tr><th>KPI</th><th>min</th><th>avg</th><th>max</th><th>unit</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _render_recommendations(recs: List[Dict[str, Any]]) -> str:
    if not recs:
        return "<p class='muted'>No recommendations.</p>"
    items = "".join(
        f"<li><strong>{_esc(r.get('action'))}</strong><br>"
        f"<span class='muted'>{_esc(r.get('rationale', ''))}</span></li>"
        for r in recs
    )
    return f"<ol>{items}</ol>"


def render_report_html(case_id: str) -> str:
    base = Path(case_manager.ARTIFACTS_DIR)
    case_dir = base / case_id
    if not case_dir.exists():
        raise FileNotFoundError(case_id)

    meta = _read_json(case_dir / "meta.json") or {}
    rca = _read_json(case_dir / "final" / "rca.json") or {}
    gh_summary = _read_json(case_dir / "groundhog" / "groundhog_summary.json") or {}
    radio_findings = _read_json(case_dir / "final" / "radio_findings.json") or []
    corr = _read_json(case_dir / "correlation" / "correlation_report.json") or {}

    pcap_file = (meta.get("pcap") or {}).get("filename") or "—"
    gh_file = (meta.get("groundhog") or {}).get("filename") or "—"
    classification = rca.get("classification") or "—"
    health_score = rca.get("health_score")
    health_status = rca.get("health_status") or "—"

    sequence_diagram = rca.get("sequence_diagram") or ""

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>DeepTrace Report · {_esc(case_id[:8])}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          color: #1a1a1a; max-width: 920px; margin: 0 auto; padding: 30px 36px 80px;
          font-size: 12.5px; line-height: 1.55; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  h2 {{ font-size: 15px; margin: 28px 0 10px; padding-bottom: 4px;
        border-bottom: 1px solid #ddd; color: #333; }}
  .sub {{ color: #666; font-size: 12px; margin-bottom: 24px; }}
  .meta {{ background: #f7f8fa; border: 1px solid #e1e4e8; border-radius: 6px;
           padding: 14px 18px; display: grid; grid-template-columns: 130px 1fr;
           gap: 6px 16px; font-size: 12px; margin-bottom: 22px; }}
  .meta dt {{ color: #666; }}
  .meta dd {{ margin: 0; word-break: break-all; }}
  .finding {{ border-left: 3px solid #5aa8ff; padding: 8px 14px; margin: 10px 0;
              background: #f5f9ff; border-radius: 0 4px 4px 0; }}
  .finding-h {{ margin-bottom: 4px; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 3px;
            background: #e1e4e8; color: #24292e; font-size: 11px; font-weight: 500; }}
  .muted {{ color: #6a737d; }}
  .small {{ font-size: 11px; }}
  ul, ol {{ margin: 6px 0 6px 18px; padding: 0; }}
  table.kpi {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  table.kpi th, table.kpi td {{ text-align: left; padding: 6px 10px; border: 1px solid #e1e4e8; }}
  table.kpi th {{ background: #f7f8fa; }}
  .narrative {{ white-space: pre-wrap; background: #fffdf3;
                border-left: 3px solid #facc15; padding: 12px 16px;
                border-radius: 0 4px 4px 0; }}
  pre.diagram {{ background: #f7f8fa; padding: 12px; border-radius: 4px;
                 font-size: 11px; overflow-x: auto; }}
  .print-bar {{ position: sticky; top: 0; background: #fff; padding: 8px 0 14px;
                margin: -30px -36px 18px; padding-left: 36px; padding-right: 36px;
                border-bottom: 1px solid #e1e4e8; display: flex; justify-content: space-between;
                align-items: center; }}
  .print-bar button {{ background: #5aa8ff; color: #fff; border: 0; padding: 7px 16px;
                       border-radius: 4px; font-size: 13px; cursor: pointer; }}
  @media print {{
    .print-bar {{ display: none; }}
    body {{ padding: 12px 0; max-width: none; font-size: 11px; }}
    h2 {{ page-break-after: avoid; }}
    .finding {{ page-break-inside: avoid; }}
    table.kpi {{ page-break-inside: avoid; }}
  }}
</style>
</head><body>
<div class="print-bar">
  <div class="muted small">Use your browser's <strong>Print → Save as PDF</strong> to export.</div>
  <button onclick="window.print()">Print / Save PDF</button>
</div>

<h1>DeepTrace Analysis Report</h1>
<div class="sub">Case <code>{_esc(case_id)}</code></div>

<dl class="meta">
  <dt>PCAP file</dt><dd>{_esc(pcap_file)}</dd>
  <dt>Groundhog file</dt><dd>{_esc(gh_file)}</dd>
  <dt>Classification</dt><dd><span class="badge">{_esc(classification)}</span></dd>
  <dt>Health</dt><dd><strong>{_esc(health_score) if health_score is not None else "—"}</strong> ({_esc(health_status)})</dd>
  <dt>Total events</dt><dd>{_esc(gh_summary.get("total_events") or "—")}</dd>
  <dt>Correlation</dt><dd>{_esc(corr.get("total_correlations") or "—")} matches · alignment {_esc(corr.get("time_alignment") or "—")}</dd>
</dl>

<h2>Executive narrative</h2>
<div class="narrative">{_esc(rca.get("executive_narrative") or "(none)")}</div>

<h2>Contributing factors</h2>
<ul>{"".join(f"<li>{_esc(x)}</li>" for x in (rca.get("contributing_factors") or [])) or "<li class='muted'>none</li>"}</ul>

<h2>Root causes</h2>
{_render_findings(rca.get("root_causes") or [])}

<h2>Radio root cause findings</h2>
{_render_radio_findings(radio_findings)}

<h2>Radio KPI statistics</h2>
{_render_kpis(gh_summary)}

<h2>Recommendations</h2>
{_render_recommendations(rca.get("recommendations") or [])}

{("<h2>Sequence diagram (Mermaid source)</h2><pre class='diagram'>" + _esc(sequence_diagram) + "</pre>") if sequence_diagram else ""}

<p class="muted small" style="margin-top:30px">Generated by DeepTrace. Subscriber identifiers in this report are anonymised (see <code>SUB_*</code>, <code>IMSI_*</code> pseudonyms).</p>
</body></html>
"""
