# Documentation updates

- **All user-facing prose lives in `docs/content/`** — a Hugo site published at https://zhaow-de.github.io/pam-keycloak-oidc/.
- **Never grow `README.md` back** — it is deliberately a stub: version line, one-paragraph overview, link to the site, Credits.
- **A change to config keys or auth behaviour updates `docs/content/` in the same change** — the prose examples too, not just the config sample.
- **Land every config-key change in BOTH `docs/content/config.md` and `docs/content/servers/keycloak-12.x.md`** — the full TOML sample is duplicated in the IdP page, indented into its numbered list, and nothing checks that the two agree.
- **New pages carry YAML front matter (`---`) with `title` and `weight`** — existing weights are 1 / 20 / 30 / 90; leave gaps for insertion.
- **Never run `hugo new`** — `docs/archetypes/default.md` emits TOML front matter with `draft = true`, contradicting every real page, and the draft would not publish.
- **New identity-provider guides go in `docs/content/servers/`** and must be added to the bullet list in `docs/content/servers/_index.md`.
- **Internal links are relative and extensionless** — `../servers/`, `../config`, `./keycloak-12.x/`; never link the `.md` path.
- **`docs/content/servers/keycloak-12.x.md` keeps an `aliases:` entry for its old misspelled path** — the page shipped for years at `/servers/keyclock-12.x/`; drop the alias and every published link and bookmark to it 404s.
- **Never edit `docs/public/` or `docs/resources/_gen/`** — gitignored stale Hugo output that a raw `grep -r` still surfaces beside the sources, and an edit there is invisible and overwritten; regenerate by running `hugo` inside `docs/`.
- **`docs/themes/hugo-book` is a pinned submodule** — never edit under it, and run `git submodule update --init --recursive` or the site will not build at all.
- **Build the site with Hugo extended, at the exact version `hugo.yml` pins** — the theme's own `hugo.toml` sets the floor and CI pins a specific build plus dart-sass; read the pin from the workflow rather than assuming, and match it to reproduce.
- **Docs deploy only from a push to `main` that touches `docs/**` or `hugo.yml`** — a docs change on `develop` or a feature branch is not live, there is no preview build, and a push touching neither path deploys nothing; never report a docs change as published without checking the run fired.
