# -*- coding: utf-8 -*-
"""attack_surface_correlation/graph.py — สร้างกราฟ attack surface (pure, lightweight)

ใช้โครงสร้าง dict ธรรมดา (nodes/edges) — ไม่พึ่ง graph database ตามสเปค
(ปริมาณข้อมูลและสถาปัตยกรรมเดิมไม่จำเป็นต้องมี) ถ้าโปรเจกต์โตค่อยเปลี่ยน backend ได้

graph:
  {graph_id, generated_iso, nodes:[{id,type,label,confidence,source_modules,
     finding_refs,metadata}], edges:[{source,target,relationship,confidence,
     ownership,hypothesis,explanation,evidence}], stats:{...}}

node ไม่ถูกสร้างจากสมมติฐานที่ไม่มีหลักฐาน — ทุก node มาจาก asset จริง, ทุก edge มาจาก
correlation ที่ผ่านกฎใน relate.py แล้ว
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_graph(assets: List[Dict[str, Any]], correlations: List[Dict[str, Any]],
                graph_id: str = "GRAPH-000001") -> Dict[str, Any]:
    """รวม asset เป็น node และ correlation เป็น edge

    edge ที่อ้าง asset_id ที่ไม่มี node จริง (เช่น target สังเคราะห์ของ shared cert/tech)
    จะถูกเก็บเป็น edge ไปยัง "virtual node" ที่ label ชัดเจน เพื่อคงความสัมพันธ์ไว้แบบ
    ตรวจสอบได้ ไม่ทิ้งข้อมูล
    """
    nodes: List[Dict[str, Any]] = []
    node_ids = set()

    # finding refs ต่อ asset (เพื่อแนบที่ node)
    finding_refs: Dict[str, List[str]] = {}
    for c in correlations:
        if c.get("relationship") == "has_finding":
            finding_refs.setdefault(c["source"], []).append(c["target"])

    for a in assets:
        nid = a["asset_id"]
        node_ids.add(nid)
        nodes.append({
            "id": nid,
            "type": a["asset_type"],
            "label": a["value"],
            "confidence": a.get("confidence", 0.0),
            "parent_domain": a.get("parent_domain", ""),
            "source_modules": a.get("source_modules", []),
            "ip_addresses": a.get("ip_addresses", []),
            "technologies": a.get("technologies", []),
            "finding_refs": finding_refs.get(nid, []),
            "metadata": a.get("metadata", {}),
        })

    edges: List[Dict[str, Any]] = []
    virtual: Dict[str, Dict[str, Any]] = {}
    for c in correlations:
        src, tgt = c["source"], c["target"]
        # target สังเคราะห์ (เช่น "tech:nginx", "...:san") -> สร้าง virtual node ครั้งเดียว
        if tgt not in node_ids and tgt not in virtual:
            virtual[tgt] = {
                "id": tgt,
                "type": "technology" if tgt.startswith("tech:") else "group",
                "label": tgt.split(":", 1)[-1] if ":" in tgt else tgt,
                "confidence": c.get("confidence", 0.0),
                "source_modules": c.get("source_modules", []),
                "virtual": True,
                "finding_refs": [],
                "metadata": {"synthetic": True},
            }
        if src not in node_ids and src not in virtual:
            continue
        edges.append({
            "source": src,
            "target": tgt,
            "relationship": c["relationship"],
            "rule": c.get("rule"),
            "confidence": c.get("confidence", 0.0),
            "ownership": c.get("ownership", "confirmed"),
            "hypothesis": c.get("hypothesis", False),
            "explanation": c.get("explanation", ""),
            "evidence": c.get("evidence", []),
            "correlation_id": c.get("correlation_id"),
        })

    nodes.extend(virtual.values())

    by_type: Dict[str, int] = {}
    for n in nodes:
        by_type[n["type"]] = by_type.get(n["type"], 0) + 1
    rel_types: Dict[str, int] = {}
    hypo = 0
    for e in edges:
        rel_types[e["relationship"]] = rel_types.get(e["relationship"], 0) + 1
        if e["hypothesis"]:
            hypo += 1

    return {
        "graph_id": graph_id,
        "generated_iso": _now(),
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes_by_type": by_type,
            "relationships_by_type": rel_types,
            "hypothesis_edges": hypo,
            "confirmed_edges": len(edges) - hypo,
        },
    }


def neighbors(graph: Dict[str, Any], node_id: str) -> List[str]:
    """คืน id ของ node ที่เชื่อมกับ node_id (ทั้งสองทิศ)"""
    out = set()
    for e in graph.get("edges", []):
        if e["source"] == node_id:
            out.add(e["target"])
        elif e["target"] == node_id:
            out.add(e["source"])
    return sorted(out)


def degree_map(graph: Dict[str, Any]) -> Dict[str, int]:
    """จำนวนเส้นเชื่อมต่อ node — ใช้หา asset ศูนย์กลาง (hub)"""
    deg: Dict[str, int] = {}
    for e in graph.get("edges", []):
        deg[e["source"]] = deg.get(e["source"], 0) + 1
        deg[e["target"]] = deg.get(e["target"], 0) + 1
    return deg
