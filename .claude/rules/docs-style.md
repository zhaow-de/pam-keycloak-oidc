# CLAUDE.md, rules, and markdown style

- **Markdown: one line per paragraph/bullet** — never hard-wrap to a column width; let the renderer wrap.
- **Escape `|` as `\|` inside a table's code spans** — GFM otherwise splits the row and silently discards the surplus cells; after editing a table carrying code, check the rendered cell count.
- **CLAUDE.md and `.claude/rules/*` are operational guidance for Claude, not human-facing docs**: the shortest imperative statement of what to DO / NOT do, one line each where possible; drop human-facing phrasing.
- **No narration in rules** — history, derivations, measurements, dates, and rationale beyond one clause do not belong in a rule file.
- **No references except operands.** Cite only what you will actually open and use: a config path, a command you run, a sibling rule you load. Never code line numbers — a line number rots silently and nothing checks it. If a code pointer is genuinely needed, name the symbol or the file, not the coordinates.
- **Keep the one-clause why** wherever the instruction would otherwise look wrong, so it does not get "corrected" later. That is not a reference.
- **Add to CLAUDE.md only what changes Claude's behavior.** Never duplicate a config's mechanics (globs, regexes, search-and-replace patterns) — that knowledge lives in the config file itself.
- **A config's absence from CLAUDE.md is the signal not to touch it** — wait for an explicit instruction before changing configs CLAUDE.md doesn't mention.
