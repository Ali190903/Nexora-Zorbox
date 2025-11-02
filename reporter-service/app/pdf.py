from __future__ import annotations

from io import BytesIO
from typing import Dict, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def build_pdf(analysis: Dict[str, Any]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    elems = []

    title = analysis.get("title") or f"ZORBOX Report: {analysis.get('id','unknown')}"
    elems.append(Paragraph(title, styles['Title']))
    elems.append(Spacer(1, 12))

    summary = analysis.get("summary") or "Executive Summary: This is an MVP auto-generated report."
    elems.append(Paragraph(summary, styles['Normal']))
    elems.append(Spacer(1, 12))

    # Prefer aggregated final score if present
    final_score = (analysis.get("final") or {}).get("total")
    final_level = (analysis.get("final") or {}).get("level")
    if final_score is not None:
        elems.append(Paragraph(f"Final Risk: {final_level or 'unknown'} ({final_score})", styles['Heading2']))
    else:
        score = analysis.get("score", {})
        total = score.get("total", 0)
        elems.append(Paragraph(f"Final Score: {total}", styles['Heading2']))
    elems.append(Spacer(1, 8))

    score = analysis.get("score", {})
    rules = score.get("rules", [])
    if rules:
        elems.append(Paragraph("Triggered Rules:", styles['Heading3']))
        for r in rules[:20]:
            desc = r.get('desc', 'rule')
            hit = r.get('hit', False)
            elems.append(Paragraph(f"- {desc}: {'HIT' if hit else 'MISS'}", styles['Normal']))

    # File info
    f = analysis.get('file') or {}
    if f:
        elems.append(Spacer(1, 10))
        elems.append(Paragraph("File Info", styles['Heading3']))
        elems.append(Paragraph(f"Name: {f.get('name','unknown')}", styles['Normal']))
        elems.append(Paragraph(f"Size: {f.get('size','?')} bytes", styles['Normal']))
        if f.get('sha256'): elems.append(Paragraph(f"SHA256: {f.get('sha256')}", styles['Normal']))

    # AI summary (if present)
    ai = analysis.get('ai') or {}
    if ai:
        elems.append(Spacer(1, 10))
        elems.append(Paragraph(f"AI Score: {ai.get('total',0)}", styles['Heading3']))
        top = ai.get('top') or []
        for k,v in top[:3]:
            elems.append(Paragraph(f"- {k}: {v}", styles['Normal']))

    # YARA hits summary
    yh = ((analysis.get('static') or {}).get('yara_hits')) or []
    if yh:
        elems.append(Spacer(1, 10))
        elems.append(Paragraph("YARA Hits:", styles['Heading3']))
        for name in yh[:20]:
            elems.append(Paragraph(f"- {name}", styles['Normal']))

    doc.build(elems)
    return buf.getvalue()
