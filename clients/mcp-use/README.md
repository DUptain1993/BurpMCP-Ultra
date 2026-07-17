# Headless `mcp-use` client for BurpMCP-Ultra

A minimal, **no-TUI** command-line client that connects to the BurpMCP-Ultra MCP
server with [`mcp-use`](https://docs.mcp-use.com/) and drives Burp Suite from a
plain-language goal, using **Venice AI** (an OpenAI-compatible endpoint) as the LLM.

Use this instead of Claude Code / Claude Desktop when you want to run the agent
**headless** — from a script, a cron job, or a one-shot command — rather than an
interactive terminal UI. You describe what you want; the agent plans and calls
BurpMCP-Ultra's MCP tools to carry it out, then prints a final summary and exits.

> This is a *separate* path from the in-extension "AI Agent" tab. The tab runs the
> Venice loop inside Burp; this client runs it externally over MCP. Either works —
> pick whichever fits your workflow.

## Prerequisites

- **Python 3.11+**
- **BurpMCP-Ultra loaded and running** in Burp (its MCP SSE server listening on
  `127.0.0.1:9876`). Open **Burp → BurpMCP-Ultra → Server** tab to get the
  connection URL and the **bearer token**.
- A **Venice AI API key** and a Venice model that supports **function/tool
  calling** (the agent drives Burp entirely through MCP tool calls).

## Install

```bash
cd clients/mcp-use
python -m venv .venv && source .venv/bin/activate      # optional but recommended
pip install -r requirements.txt
```

## Configure

```bash
cp .env.example .env
# then edit .env and fill in:
#   BURP_MCP_TOKEN   (from the BurpMCP-Ultra -> Server tab)
#   VENICE_API_KEY   (from https://venice.ai)
#   VENICE_MODEL     (a model whose capabilities include supportsFunctionCalling)
```

`.env` is auto-loaded (via `python-dotenv`). You can also export the same
variables in your shell instead of using a file.

### Picking a Venice model that supports tool calling

Only models with `supportsFunctionCalling: true` will work. List them with:

```bash
curl -s https://api.venice.ai/api/v1/models?type=text \
  -H "Authorization: Bearer $VENICE_API_KEY" \
  | python -c "import sys,json; [print(m['id']) for m in json.load(sys.stdin)['data'] if m.get('model_spec',{}).get('capabilities',{}).get('supportsFunctionCalling')]"
```

Put one of the printed ids in `VENICE_MODEL`.

## Run

```bash
# goal as arguments
python burp_agent.py "check the login endpoint for SQLi and look for IDOR across the test accounts"

# goal piped on stdin
echo "enumerate the GraphQL schema and report injection points" | python burp_agent.py

# override the step budget for a bigger task
python burp_agent.py --max-steps 40 "crawl the target, then summarise likely vulnerabilities"
```

The agent respects Burp's target scope and the operator's destructive-action
policy exactly as any MCP client does — those gates live server-side in the
extension, not in this client.

## How it connects

BurpMCP-Ultra exposes a **plain MCP SSE** transport: the SSE stream is the **root
path `/`** (not `/sse`), and every request needs the bearer token. The client
therefore pins `"type": "sse"` and sends `Authorization: Bearer <token>`:

```python
MCPClient.from_dict({
    "mcpServers": {
        "burp": {
            "type": "sse",
            "url": "http://127.0.0.1:9876/",
            "headers": {"Authorization": "Bearer <token>"},
        }
    }
})
```

Venice is wired in as a standard OpenAI-compatible LangChain model:

```python
ChatOpenAI(model=VENICE_MODEL, base_url="https://api.venice.ai/api/v1", api_key=VENICE_API_KEY)
```

## Troubleshooting

- **`Environment variable ... is required`** — fill in `.env` (or export the var).
- **401 / connection refused** — the token is wrong/expired, or BurpMCP-Ultra
  isn't running. Re-copy the token from the Server tab; confirm the port (9876
  primary / 9877 secondary / 9900 if you use the bundled Caddy proxy).
- **Authorization header stripped by a proxy** — BurpMCP-Ultra also accepts the
  token as a query param; set `BURP_MCP_URL=http://127.0.0.1:9876/?token=<token>`.
- **Model errors about tools / function calling** — your `VENICE_MODEL` doesn't
  support tool calling. Pick one flagged `supportsFunctionCalling` (see above).
- **SSE disconnects on long runs** — front BurpMCP-Ultra with the bundled Caddy
  reverse proxy (`configs/Caddyfile`) and point `BURP_MCP_URL` at `:9900`.
