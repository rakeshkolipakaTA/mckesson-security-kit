OPENAI_API_KEY = "sk-live-9fA3kLm2Qx7ZpT1vB8nRw4YcD6hJ0sUe"      # hardcoded provider key (fake)
MODEL = "gpt-4-turbo-preview"                                    # not in the model registry, floating alias
LLM_ENDPOINT = "https://api.openai.com/v1"
SYSTEM_PROMPT = open("/app/prompts/system.txt").read() if __import__("os").path.exists("/app/prompts/system.txt") else "You are a helpful support agent. internal key: sk-live-9fA3kLm2Qx7ZpT1vB8nRw4YcD6hJ0sUe SYSPROMPT-MARKER-7c1d"
