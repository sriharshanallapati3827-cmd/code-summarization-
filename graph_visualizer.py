"""
graph_visualizer.py - Physics-Based Interactive PDG Graph Visualizer
===================================================================
Renders an interactive, physics-driven Program Dependence Graph (PDG)
using vis.js Network.

Features:
  - Interactive physics canvas (drag, bounce, zoom, pan)
  - Color-coded node typology (Root, Function, Branch, Assign, Return, Tainted)
  - Color-coded edge semantics (Control flow, Data dependencies, Taint tracking)
  - Interactive inspector: clicking any node reveals incoming/outgoing dependencies
  - View controls: toggle Control edges, Data edges, or isolate Tainted pathways
  - Generates embeddable HTML string for Streamlit or standalone .html file
"""

import json
from typing import Dict, List, Optional, Any


def generate_pdg_html(
    pdg_graph: Dict[str, Any],
    tainted_flows: Optional[List[Dict[str, Any]]] = None,
    height: str = "550px",
    background: str = "#0f172a"
) -> str:
    """
    Generates a full interactive HTML snippet rendering the PDG with vis.js physics.
    """
    if tainted_flows is None:
        tainted_flows = []

    # Map tainted node IDs
    tainted_node_ids = set()
    tainted_edge_pairs = set()
    for flow in tainted_flows:
        src = flow.get("source_node")
        tgt = flow.get("sink_node")
        var = flow.get("variable")
        if src:
            tainted_node_ids.add(src)
        if tgt:
            tainted_node_ids.add(tgt)
        if src and tgt:
            tainted_edge_pairs.add((src, tgt))

    raw_nodes = pdg_graph.get("nodes", {})
    raw_edges = pdg_graph.get("edges", [])

    vis_nodes = []
    for node_id, label in raw_nodes.items():
        is_tainted = node_id in tainted_node_ids
        clean_label = label.replace("\n", " ").strip()
        
        # Categorize node style
        if is_tainted:
            color = {"background": "#dc2626", "border": "#ef4444", "highlight": {"background": "#b91c1c", "border": "#f87171"}}
            shape = "box"
            font = {"color": "#ffffff", "face": "monospace", "bold": True}
            title = f"CRITICAL: Tainted Node {node_id}\n{clean_label}"
        elif node_id == "root":
            color = {"background": "#334155", "border": "#64748b", "highlight": {"background": "#475569", "border": "#94a3b8"}}
            shape = "hexagon"
            font = {"color": "#f8fafc", "face": "monospace"}
            title = "Program Entry Root"
        elif clean_label.startswith("Function"):
            color = {"background": "#2563eb", "border": "#3b82f6", "highlight": {"background": "#1d4ed8", "border": "#60a5fa"}}
            shape = "box"
            font = {"color": "#ffffff", "face": "monospace", "bold": True}
            title = f"Function Definition: {clean_label}"
        elif clean_label.startswith("If") or clean_label.startswith("For") or clean_label.startswith("While"):
            color = {"background": "#d97706", "border": "#f59e0b", "highlight": {"background": "#b45309", "border": "#fbbf24"}}
            shape = "diamond"
            font = {"color": "#ffffff", "face": "monospace"}
            title = f"Control Decision Branch: {clean_label}"
        elif clean_label.startswith("Return"):
            color = {"background": "#7c3aed", "border": "#8b5cf6", "highlight": {"background": "#6d28d9", "border": "#a78bfa"}}
            shape = "box"
            font = {"color": "#ffffff", "face": "monospace"}
            title = f"Return Statement: {clean_label}"
        else:
            # Assign / Expr
            color = {"background": "#059669", "border": "#10b981", "highlight": {"background": "#047857", "border": "#34d399"}}
            shape = "box"
            font = {"color": "#ffffff", "face": "monospace"}
            title = f"Statement: {clean_label}"

        # Shorten label for node display
        display_label = f"{node_id}\n{clean_label[:28]}..." if len(clean_label) > 28 else f"{node_id}\n{clean_label}"

        vis_nodes.append({
            "id": node_id,
            "label": display_label,
            "title": title,
            "shape": shape,
            "color": color,
            "font": font,
            "margin": 10,
            "shadow": {"enabled": True, "color": "rgba(0,0,0,0.5)", "size": 6}
        })

    vis_edges = []
    for idx, e in enumerate(raw_edges):
        src = e.get("source")
        tgt = e.get("target")
        kind = e.get("kind")
        lbl = e.get("label", "")
        is_tainted_edge = (src, tgt) in tainted_edge_pairs

        if is_tainted_edge:
            color = {"color": "#ef4444", "highlight": "#dc2626"}
            width = 3.5
            dashes = False
            title = f"TAINT ALERT: Insecure data flow of '{lbl}'"
            edge_lbl = f"⚠ {lbl}"
        elif kind == "Control":
            color = {"color": "#38bdf8", "highlight": "#0ea5e9"}
            width = 1.8
            dashes = [5, 5]
            title = f"Control Flow: {src} -> {tgt}"
            edge_lbl = ""
        else:
            # Data flow
            color = {"color": "#4ade80", "highlight": "#22c55e"}
            width = 2.0
            dashes = False
            title = f"Data Dependency: {src} -> {tgt} ('{lbl}')"
            edge_lbl = lbl

        vis_edges.append({
            "id": f"e{idx}",
            "from": src,
            "to": tgt,
            "label": edge_lbl,
            "kind": kind,
            "is_tainted": is_tainted_edge,
            "title": title,
            "color": color,
            "width": width,
            "dashes": dashes,
            "arrows": "to",
            "smooth": {"type": "cubicBezier", "roundness": 0.3},
            "font": {"color": "#cbd5e1", "size": 11, "face": "monospace", "align": "horizontal", "strokeWidth": 0}
        })

    nodes_json = json.dumps(vis_nodes)
    edges_json = json.dumps(vis_edges)

    html_template = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{
      margin: 0;
      padding: 0;
      background-color: {background};
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #e2e8f0;
      overflow: hidden;
    }}
    #pdg-container {{
      width: 100%;
      height: {height};
      position: relative;
    }}
    .pdg-toolbar {{
      position: absolute;
      top: 10px;
      left: 10px;
      z-index: 100;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(8px);
      padding: 8px 14px;
      border-radius: 8px;
      border: 1px solid #334155;
      display: flex;
      gap: 12px;
      align-items: center;
      font-size: 12px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }}
    .pdg-toolbar label {{
      display: flex;
      align-items: center;
      gap: 5px;
      cursor: pointer;
      user-select: none;
    }}
    .legend {{
      position: absolute;
      bottom: 12px;
      right: 12px;
      z-index: 100;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(8px);
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid #334155;
      font-size: 11px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }}
    .line-dash {{
      width: 16px;
      height: 2px;
      border-top: 2px dashed #38bdf8;
      display: inline-block;
    }}
    .line-solid {{
      width: 16px;
      height: 2px;
      background: #4ade80;
      display: inline-block;
    }}
    .line-taint {{
      width: 16px;
      height: 3px;
      background: #ef4444;
      display: inline-block;
    }}
    #node-details {{
      position: absolute;
      top: 10px;
      right: 10px;
      z-index: 100;
      background: rgba(15, 23, 42, 0.9);
      backdrop-filter: blur(8px);
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid #3b82f6;
      font-size: 12px;
      display: none;
      max-width: 280px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    }}
  </style>
</head>
<body>
  <div id="pdg-container">
    <div class="pdg-toolbar">
      <span style="font-weight: 600; color: #38bdf8;">PDG Physics Visualizer</span>
      <label><input type="checkbox" id="toggle-control" checked /> Control Edges</label>
      <label><input type="checkbox" id="toggle-data" checked /> Data Edges</label>
      <label><input type="checkbox" id="toggle-taint-only" /> Only Tainted</label>
      <button onclick="network.fit({{animation: true}})" style="background: #1e293b; color: #e2e8f0; border: 1px solid #475569; padding: 3px 8px; border-radius: 4px; cursor: pointer; font-size: 11px;">Reset View</button>
    </div>

    <div id="node-details"></div>

    <div class="legend">
      <div style="font-weight: 600; color: #94a3b8; margin-bottom: 2px;">PDG Semantics</div>
      <div class="legend-item"><span class="dot" style="background:#2563eb;"></span> Function Def</div>
      <div class="legend-item"><span class="dot" style="background:#d97706;"></span> Control Branch</div>
      <div class="legend-item"><span class="dot" style="background:#059669;"></span> Assignment / Stmt</div>
      <div class="legend-item"><span class="dot" style="background:#dc2626;"></span> Insecure / Tainted</div>
      <div class="legend-item"><span class="line-dash"></span> Control Edge</div>
      <div class="legend-item"><span class="line-solid"></span> Data Flow</div>
      <div class="legend-item"><span class="line-taint"></span> Tainted Flow</div>
    </div>
  </div>

  <script type="text/javascript">
    const rawNodes = {nodes_json};
    const rawEdges = {edges_json};

    const container = document.getElementById("pdg-container");
    const nodeDetails = document.getElementById("node-details");

    const nodesDataSet = new vis.DataSet(rawNodes);
    const edgesDataSet = new vis.DataSet(rawEdges);

    const data = {{
      nodes: nodesDataSet,
      edges: edgesDataSet
    }};

    const options = {{
      physics: {{
        enabled: true,
        solver: "barnesHut",
        barnesHut: {{
          gravitationalConstant: -2800,
          centralGravity: 0.25,
          springLength: 130,
          springConstant: 0.04,
          damping: 0.12,
          avoidOverlap: 0.4
        }},
        stabilization: {{
          iterations: 150,
          updateInterval: 25
        }}
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 100,
        navigationButtons: true,
        keyboard: true
      }}
    }};

    const network = new vis.Network(container, data, options);

    // Node selection inspector
    network.on("selectNode", function(params) {{
      if (params.nodes.length > 0) {{
        const nodeId = params.nodes[0];
        const node = nodesDataSet.get(nodeId);
        nodeDetails.style.display = "block";
        nodeDetails.innerHTML = `<div style="font-weight:bold; color:#38bdf8; margin-bottom:4px;">Node Inspector: ${{nodeId}}</div>
                                 <div style="font-size:11px; color:#cbd5e1; word-break:break-word;">${{node.title.replace(/\\n/g, "<br/>")}}</div>`;
      }}
    }});

    network.on("deselectNode", function() {{
      nodeDetails.style.display = "none";
    }});

    // Toolbar filters
    const ctrlCheck = document.getElementById("toggle-control");
    const dataCheck = document.getElementById("toggle-data");
    const taintCheck = document.getElementById("toggle-taint-only");

    function applyFilter() {{
      const showCtrl = ctrlCheck.checked;
      const showData = dataCheck.checked;
      const taintOnly = taintCheck.checked;

      const filtered = rawEdges.filter(e => {{
        if (taintOnly && !e.is_tainted) return false;
        if (e.kind === "Control" && !showCtrl) return false;
        if (e.kind === "Data" && !showData) return false;
        return true;
      }});

      edgesDataSet.clear();
      edgesDataSet.add(filtered);
    }}

    ctrlCheck.addEventListener("change", applyFilter);
    dataCheck.addEventListener("change", applyFilter);
    taintCheck.addEventListener("change", applyFilter);
  </script>
</body>
</html>
"""
    return html_template


def save_pdg_html(
    pdg_graph: Dict[str, Any],
    output_path: str,
    tainted_flows: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Saves the interactive PDG visualization to a local HTML file."""
    html = generate_pdg_html(pdg_graph, tainted_flows=tainted_flows, height="100vh")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


if __name__ == "__main__":
    from pdg_extractor import extract_pdg_graph
    sample = """
def authenticate(username, token):
    valid = False
    if len(token) > 10:
        valid = True
    result = eval(token)
    return valid
"""
    graph = extract_pdg_graph(sample)
    taints = [
        {"source_node": "N0", "sink_node": "N3", "variable": "token", "description": "Tainted parameter flow into eval"}
    ]
    out_file = "interactive_pdg_preview.html"
    save_pdg_html(graph, out_file, tainted_flows=taints)
    print(f"Interactive PDG generated and saved to: {out_file}")
