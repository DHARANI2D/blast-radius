# Open-source disclosure

All BlastRadius source code in this repository was written for the HPE Agentic AI Hackathon India 2026. It contains no pre-existing project code. The components below are third-party open source, used unmodified as libraries.

## Runtime dependencies

| Component | Version tested | License | Used for |
|---|---|---|---|
| LangGraph (+ langgraph-checkpoint, langchain-core) | 1.2.16 | MIT | Supervisor state machine, checkpointing, human-in-the-loop interrupts |
| MCP Python SDK (`mcp`) | 2.3.0 | MIT | Domain MCP servers and client sessions |
| NetworkX | 3.7 | BSD-3-Clause | Dependency graph and reachability simulation |
| Pydantic | 2.13 | MIT | Schemas for every LLM output |
| PyYAML | 6.0 | MIT | Policy file |
| Streamlit | 1.66 | Apache-2.0 | Control Tower UI (Graphviz rendering is bundled in Streamlit's front end) |
| pandas | 3.0 | BSD-3-Clause | UI tables and charts |
| Vega-Altair | 6.0 (installed with Streamlit) | BSD-3-Clause | Statistical-judge band chart in the UI |

## Development tooling

| Component | License | Used for |
|---|---|---|
| pytest | MIT | Test suite |

## Standard library only

The OpenAI-compatible and Azure OpenAI LLM client (`blastradius/llm.py`, including function calling) uses `urllib`. BM25 retrieval, the SQLite ledger, the HMAC signatures and the A2A JSON-RPC endpoint (`http.server`) also use only the Python standard library. The statistics (Mann-Whitney U with an exact permutation test for small samples, Wilson intervals), the simulated-annealing optimiser and the Monte Carlo pre-mortem are implemented from scratch in pure Python: no numpy or scipy.

## External services and data

- **LLM endpoints:** none are bundled. Configure an HPE-approved endpoint (see README). The default offline mode makes no network calls.
- **HPE GreenLake MCP servers (`HewlettPackard/gl-mcp`, Apache-2.0):** optional, read-only, not bundled and not vendored. BlastRadius calls only the devices server's `getdevicesv1` tool (or `invoke_dynamic_tool` for it when the server runs in dynamic mode), and only if `BR_GL_MCP_URL` or `BR_GL_MCP_CMD` is set (see README).
- **Agent2Agent (A2A) protocol:** `blastradius/a2a_server.py` implements the JSON-RPC methods and agent card from the public specification; no A2A SDK is used.
- **Data:** all twin, release-note, advisory and incident data in `data/` is synthetic and was created for this project.
