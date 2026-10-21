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

## Development and documentation tooling

| Component | License | Used for |
|---|---|---|
| pytest | MIT | Test suite |
| python-docx | MIT | `scripts/build_abstract.py` fills the official abstract template |
| Playwright for Python | Apache-2.0 | `scripts/capture_screenshots.py` |

## Standard library only

The OpenAI-compatible and Azure OpenAI LLM client (`blastradius/llm.py`) uses `urllib`. BM25 retrieval, the SQLite ledger and the HMAC signatures also use only the Python standard library.

## External services and data

- **LLM endpoints:** none are bundled. Configure an HPE-approved endpoint (see README). The default offline mode makes no network calls.
- **HPE GreenLake MCP server (`HewlettPackard/gl-mcp`):** optional, read-only, not bundled. It is only contacted if `BR_GL_MCP_URL` or `BR_GL_MCP_CMD` is set.
- **Data:** all twin, release-note, advisory and incident data in `data/` is synthetic and was created for this project.
