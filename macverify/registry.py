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
    selected = list(DOMAINS)
    if only:
        wanted = [name for name in only if name in DOMAINS]
        unknown = [name for name in only if name not in DOMAINS]
        selected = [name for name in DOMAINS if name in wanted]
        return selected, unknown
    if skip:
        unknown = [name for name in skip if name not in DOMAINS]
        selected = [name for name in DOMAINS if name not in skip]
        return selected, unknown
    return selected, []
