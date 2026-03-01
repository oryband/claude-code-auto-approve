# approve-compound-bash

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook that auto-approves compound Bash commands when every sub-command is in your allow list and none are in your deny list.

## The problem

Claude Code matches `Bash(cmd *)` permissions against the **full command string**. `ls | grep foo` doesn't match `Bash(ls *)` or `Bash(grep *)`, so you get prompted even though both commands are individually allowed. Same for `nvm use && yarn test`, `git log | head`, `mkdir -p dir && cd dir`, etc.

This hook parses compound commands into segments and checks each one.

## Install

Requires **bash 4.3+** (auto-detected; re-execs with Homebrew bash on macOS if needed), [shfmt](https://github.com/mvdan/sh), and [jq](https://jqlang.github.io/jq/).

```bash
brew install shfmt jq
```

Copy the script somewhere and register it in `~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "~/.claude/scripts/approve-compound-bash.sh",
        "timeout": 3
      }]
    }]
  },
  "permissions": {
    "allow": [
      "Bash(ls *)", "Bash(grep *)", "Bash(git *)" // ...
    ],
    "deny": [
      "Bash(git push --force *)", "Bash(rm -rf / *)" // ...
    ]
  }
}
```

The hook reads permissions from all settings layers (global, global local, project, project local), supports all permission formats (`Bash(cmd *)`, `Bash(cmd:*)`, `Bash(cmd)`), and strips env var prefixes (`NODE_ENV=prod npm test` matches `npm`).

## How it decides

**Simple commands** (no `|`, `&`, `;`, `` ` ``, `$(`) are checked directly against your prefix lists. No parsing overhead.

**Compound commands** are parsed into a JSON AST by shfmt, walked by a jq filter that extracts every sub-command (including inside `$(...)`, `<(...)`, subshells, if/for/while/case bodies, `bash -c` arguments, etc.), then each segment is checked.

Three outcomes:

- **Approve** — all segments in allow list, none in deny list. Command runs.
- **Deny** — any segment matches the deny list. Command is blocked.
- **Fall through** — segment is unknown (not in allow or deny), or parse failed. Claude Code shows its normal permission prompt.

On any error the hook falls through. It never approves something it can't fully analyze.

## Debugging

Extract sub-commands from a compound command:

```bash
echo 'nvm use && yarn test' | ./approve-compound-bash.sh parse
# nvm use
# yarn test
```

Verbose mode shows matching decisions on stderr:

```bash
echo '{"tool_input":{"command":"ls | grep foo"}}' | ./approve-compound-bash.sh --debug
```

## Testing

97 tests across parsing, permissions, and security. Requires [BATS](https://bats-core.readthedocs.io/).

```bash
bats test/
```

## Known limitations

**`bash -c` on simple path**: `bash -c 'echo hello'` has no shell metacharacters, so it takes the fast path and matches against the prefix list as-is without recursing into the inner command. Don't add `bash`, `sh`, or `zsh` to your allow list.

## Credits

Based on [claude-code-plus](https://github.com/AbdelrahmanHafez/claude-code-plus) (MIT). Key differences: deny list support, active deny for compounds, fast path for simple commands, falls through on empty parse (the original approves), settings layer support, env var stripping, and a test suite.
