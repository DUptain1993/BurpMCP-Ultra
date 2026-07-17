#!/usr/bin/env python3
"""
Headless mcp-use client for BurpMCP-Ultra.

Connects to the BurpMCP-Ultra MCP SSE server and drives Burp Suite from a
plain-language goal, using Venice AI (an OpenAI-compatible endpoint) as the LLM.
This is an alternative to using Claude Code / Claude Desktop as the MCP client.

No TUI and no interactive chat loop: you pass the goal on the command line (or
pipe it on stdin), the agent runs to completion, the final answer is printed,
and the process exits — suitable for scripting and automation.

Usage:
    python burp_agent.py "check the login endpoint for SQLi and look for IDOR"
    echo "enumerate the GraphQL schema and report injection points" | python burp_agent.py
    python burp_agent.py --max-steps 40 "crawl the target and summarise findings"

Configuration comes from environment variables (see .env.example); a local
.env file is auto-loaded if python-dotenv is installed:

    BURP_MCP_URL     BurpMCP-Ultra SSE endpoint (default http://127.0.0.1:9876/)
    BURP_MCP_TOKEN   bearer token from the BurpMCP-Ultra -> Server tab (required)
    VENICE_API_KEY   your Venice AI API key (required)
    VENICE_MODEL     a Venice model that supports function/tool calling (required)
    VENICE_BASE_URL  Venice API base URL (default https://api.venice.ai/api/v1)
    VENICE_TEMPERATURE  sampling temperature (default 0.2)
    AGENT_MAX_STEPS  max agent tool-calling steps per run (default 25)
"""
import argparse
import asyncio
import os
import sys

# Optional: auto-load a local .env so secrets don't have to be exported by hand.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

try:
    from langchain_openai import ChatOpenAI
    from mcp_use import MCPAgent, MCPClient
except ImportError as exc:
    sys.exit(
        f"Missing dependency: {exc}.\n"
        "Install the client dependencies first:\n"
        "    pip install -r requirements.txt"
    )


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(
            f"Environment variable {name} is required but not set. "
            "Copy .env.example to .env and fill it in (or export it)."
        )
    return value


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Drive BurpMCP-Ultra from a natural-language goal via mcp-use + Venice AI (headless)."
    )
    parser.add_argument(
        "goal",
        nargs="*",
        help="What you want the agent to do. If omitted, the goal is read from stdin.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=int(os.environ.get("AGENT_MAX_STEPS", "25")),
        help="Maximum agent tool-calling steps for this run (default: %(default)s).",
    )
    return parser.parse_args()


def _resolve_goal(args: argparse.Namespace) -> str:
    if args.goal:
        return " ".join(args.goal).strip()
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped
    sys.exit(
        'No goal provided. Example:\n'
        '    python burp_agent.py "scan the target for SQL injection and report findings"'
    )


async def main() -> None:
    args = _parse_args()
    goal = _resolve_goal(args)

    burp_url = os.environ.get("BURP_MCP_URL", "http://127.0.0.1:9876/").strip()
    burp_token = _require("BURP_MCP_TOKEN")
    venice_key = _require("VENICE_API_KEY")
    venice_model = _require("VENICE_MODEL")
    venice_base = os.environ.get("VENICE_BASE_URL", "https://api.venice.ai/api/v1").strip()
    temperature = float(os.environ.get("VENICE_TEMPERATURE", "0.2"))

    # BurpMCP-Ultra exposes a plain MCP SSE transport (SSE stream at the root path
    # "/", not "/sse") that requires the bearer token on every request. We pin
    # "type": "sse" so mcp-use never tries Streamable HTTP against this SSE-only
    # server, and pass the token as an Authorization header. If your network strips
    # Authorization headers, BurpMCP-Ultra also accepts the token as a ?token= query
    # param — append it to BURP_MCP_URL as e.g. http://127.0.0.1:9876/?token=<token>.
    client = MCPClient.from_dict(
        {
            "mcpServers": {
                "burp": {
                    "type": "sse",
                    "url": burp_url,
                    "headers": {"Authorization": f"Bearer {burp_token}"},
                }
            }
        }
    )

    # Venice AI is OpenAI-compatible, so LangChain's ChatOpenAI works by pointing it
    # at Venice's base_url. The model MUST support tool/function calling — mcp-use
    # drives Burp entirely through MCP tool calls. Use a Venice model whose
    # capabilities include supportsFunctionCalling (see the /models endpoint).
    llm = ChatOpenAI(
        model=venice_model,
        base_url=venice_base,
        api_key=venice_key,
        temperature=temperature,
    )

    agent = MCPAgent(llm=llm, client=client, max_steps=args.max_steps)

    try:
        result = await agent.run(goal)
        print(result)
    finally:
        # Always tear down the SSE session cleanly on exit.
        try:
            await client.close_all_sessions()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
