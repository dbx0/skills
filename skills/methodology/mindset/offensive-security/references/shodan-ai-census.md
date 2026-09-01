# Shodan AI Infrastructure Census (May 2026)

Exposed AI services on the internet, ranked by Shodan count. Useful for understanding what scanners are looking for and what attack surface is most common.

## Exposed AI Services Ranking

| Rank | Service | Shodan Hits | Typical Port | Notes |
|---|---|---|---|---|
| 1 | Ollama | 210,157 | 11434 | #1 exposed AI target by far |
| 2 | ComfyUI | 204,799 | 7860 | AI image generation workflows |
| 3 | Grafana | 116,696 | 3000 | Monitoring (often paired with AI stacks) |
| 4 | Streamlit | 106,216 | 8501 | Data/AI app dashboards |
| 5 | Flowise | 33,215 | 3000/8080 | No-code LangChain builder |
| 6 | Jupyter | 10,535 | 8888 | Notebook servers |
| 7 | Dify | 2,389 | 5000 | AI app development platform |
| 8 | LiteLLM | 2,341 | 4000 | LLM API proxy |
| 9 | Gradio | 2,284 | 7860 | ML demo UIs |
| 10 | Stable Diffusion WebUI | 571 | 7860 | Image generation |
| 11 | MLflow | 356 | 5000 | Experiment tracking |
| 12 | n8n | 338 | 5678 | Workflow automation |
| 13 | vLLM | 12 | 8000/8080 | LLM inference engine |
| 14 | LangServe | 3 | 8000 | LangChain serving (early adoption) |

## Key Insights

- **Ollama dominates**: 210K+ exposed instances makes it the #1 target for AI-focused scanners
- **ComfyUI is #2**: AI image gen is massively exposed, nearly matches Ollama
- **Flowise is #3 at 33K**: No-code AI workflow tools are growing fast and left exposed
- **Monitoring stack exposure**: Grafana + Streamlit combined = 220K+ exposed dashboards
- **Newer inference engines** (vLLM, LangServe) barely exposed — still early adoption
- Scanners probe for ALL of these simultaneously — a typical AI recon sweep hits 10+ frameworks per target

## Honeypot Observations

Common scanner behavior on exposed AI ports:
- Single-probe hits: most scanners send 1 request per framework, move on if no response
- Multi-hit retries: Dahua camera config (7 hits), MCP endpoints (7 hits) — something responded and they came back
- MCP (Model Context Protocol) is emerging as a new scan target — `.well-known/mcp.json` discovery pattern
- IP camera AI analytics (Dahua/Hikvision/Axis) probed alongside LLMs — same bots scan both

## Shodan Query Examples

```bash
shodan count port:11434                          # Ollama
shodan count 'http.title:Flowise'                 # Flowise
shodan count 'http.title:Dify'                    # Dify
shodan count port:11434 'http.html:ollama'        # Confirmed Ollama
shodan count 'http.html:gradio'                   # Gradio apps
shodan count port:8501 'http.title:Streamlit'     # Streamlit apps
```

Collected: May 2026 from Kali box (192.168.0.8) with 89 query credits.
