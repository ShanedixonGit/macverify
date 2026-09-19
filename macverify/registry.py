import importlib

DOMAINS = (
    "toolchain",
    "packages",
    "shell_env",
    "hardware",
    "storage",
    "services",
    "containers",
    "network",
    "security",
    "identity",
    "secrets",
    "permissions",
    "claude_code",
    "github_copilot",
    "openai_codex",
    "ai_assistants",
)

AI_ASSISTANT_DOMAINS = ("claude_code", "github_copilot", "openai_codex", "ai_assistants")


def load(domain):
    return importlib.import_module("%s.collectors.%s" % (__package__, domain))


def resolve(only=None, skip=None):
    unknown = [name for name in list(only or []) + list(skip or []) if name not in DOMAINS]
    selected = list(DOMAINS)
    if only:
        wanted = set(only)
        selected = [name for name in selected if name in wanted]
    if skip:
        unwanted = set(skip)
        selected = [name for name in selected if name not in unwanted]
    return selected, unknown
