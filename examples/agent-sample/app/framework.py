"""Minimal stand-in for an agent framework's @tool decorator (LangChain/MCP style) so no heavy dependency is needed."""
REGISTRY = {}


def tool(fn):
    REGISTRY[fn.__name__] = fn
    return fn
