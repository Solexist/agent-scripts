#!/usr/bin/env python3
"""beforeShellExecution hook: 拦截并校验 git 命令。

功能：
1. 禁止危险 git 命令（可扩展列表）
2. 禁止 git add .（要求显式列出文件）
3. git push 弹窗确认
4. git commit message 格式校验
"""

import json
import re
import shlex
import sys

# ── 配置区 ──────────────────────────────────────────────────

# 完全禁止的 git 子命令 + 参数组合（正则匹配整条命令）
BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"\bgit\s+push\s+.*--force\b", "禁止 force push"),
    (r"\bgit\s+push\s+.*-f\b", "禁止 force push"),
    (r"\bgit\s+reset\s+--hard\b", "禁止 hard reset"),
    (r"\bgit\s+clean\b", "禁止 git clean"),
    (r"\bgit\s+checkout\s+--\s+\.", "禁止 git checkout -- .（会丢弃所有修改）"),
    (r"\bgit\s+restore\s+\.", "禁止 git restore .（会丢弃所有修改）"),
    (r"\bgit\s+stash\b", "避免手动 git stash"),
    (r"\bgit\s+commit\s+--amend\b", "禁止 amend，除非用户明确要求"),
    (r"\bgit\s+rebase\b", "禁止 rebase，除非用户明确要求"),
    (r"\bgit\s+merge\b", "禁止 merge，除非用户明确要求"),
    (r"\bgit\s+branch\s+-[dD]\b", "禁止删除分支，除非用户明确要求"),
]

# git add 后禁止的参数
ADD_BLOCKED_ARGS = {".", "-A", "--all", "-u", "--update", ":/"}

# commit message 格式：[AI] <type>: <描述>
# type 允许列表
COMMIT_TYPES = {"feat", "fix", "refactor", "docs", "test", "style", "perf", "build", "ci", "chore"}
COMMIT_MSG_PATTERN = re.compile(
    r"^\[AI\]\s+(" + "|".join(COMMIT_TYPES) + r"):\s+\S"
)

# 需要弹窗确认的命令
ASK_PATTERNS: list[tuple[str, str]] = [
    (r"\bgit\s+push\b", "git push 需要确认"),
    (r"\bgit\s+checkout\b", "git checkout 需要确认"),
]

# ── 逻辑区 ──────────────────────────────────────────────────


def respond(permission: str, user_message: str = "", agent_message: str = "") -> None:
    result: dict[str, object] = {"continue": True, "permission": permission}
    if user_message:
        result["user_message"] = user_message
    if agent_message:
        result["agent_message"] = agent_message
    print(json.dumps(result))
    sys.exit(0)


def extract_commit_message(command: str) -> str | None:
    """从 git commit 命令中提取 -m 参数的值。

    支持 -m "msg"、-m 'msg'、heredoc 等常见写法。
    """
    # 处理 heredoc 格式: git commit -m "$(cat <<'EOF'\n...\nEOF\n)"
    heredoc_match = re.search(
        r"""-m\s+"\$\(cat\s*<<\s*'?(\w+)'?\s*\n(.*?)\n\1\s*\)""",
        command,
        re.DOTALL,
    )
    if heredoc_match:
        return heredoc_match.group(2).strip()

    # 处理普通 -m "msg" 或 -m 'msg'
    try:
        args = shlex.split(command)
    except ValueError:
        return None

    for i, arg in enumerate(args):
        if arg == "-m" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-m") and len(arg) > 2:
            return arg[2:]

    return None


def check_git_command(command: str) -> None:
    """检查 git 命令并做出响应。"""
    cmd_stripped = command.strip()

    # 不是 git 命令，放行
    if not re.search(r"\bgit\s", cmd_stripped) and not cmd_stripped.startswith("git "):
        respond("allow")

    # 1. 检查完全禁止的命令
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            respond(
                "deny",
                user_message=f"Git 命令被拦截: {reason}",
                agent_message=f"命令被 git-guard hook 拒绝: {reason}。如需执行，请获得用户明确许可。",
            )

    # 2. 检查 git add .
    if re.search(r"\bgit\s+add\b", cmd_stripped):
        try:
            args = shlex.split(cmd_stripped)
        except ValueError:
            args = cmd_stripped.split()

        git_idx = next((i for i, a in enumerate(args) if a == "git"), None)
        if git_idx is not None:
            add_args = args[git_idx + 2:]  # git add 之后的参数
            for arg in add_args:
                if arg.startswith("-") and arg not in ADD_BLOCKED_ARGS:
                    continue
                if arg in ADD_BLOCKED_ARGS:
                    respond(
                        "deny",
                        user_message=f'git add 禁止使用 "{arg}"，请显式列出要添加的文件',
                        agent_message=(
                            f'git add 的参数 "{arg}" 被 git-guard hook 拒绝。'
                            "你必须显式列出要暂存的文件路径，例如: git add src/foo.py src/bar.py"
                        ),
                    )

    # 3. 检查 commit message 格式
    if re.search(r"\bgit\s+commit\b", cmd_stripped):
        msg = extract_commit_message(cmd_stripped)
        if msg is not None and not COMMIT_MSG_PATTERN.match(msg):
            respond(
                "deny",
                user_message=f"Commit message 格式不符合规范",
                agent_message=(
                    f"Commit message 被 git-guard hook 拒绝。"
                    f"当前 message: {msg!r}\n"
                    f"要求格式: [AI] <type>: <简短描述>\n"
                    f"允许的 type: {', '.join(sorted(COMMIT_TYPES))}\n"
                    f"示例: [AI] feat: 添加用户登录功能"
                ),
            )

    # 4. 需要确认的命令
    for pattern, reason in ASK_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            respond(
                "ask",
                user_message=f"{reason}: {cmd_stripped}",
            )

    # 其余 git 命令放行
    respond("allow")


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        respond("allow")
        return

    command = payload.get("command", "")
    check_git_command(command)


if __name__ == "__main__":
    main()
