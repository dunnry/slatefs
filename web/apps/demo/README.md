# SlateFS consumer demo

The Vite application is a standalone same-origin consumer shell. It owns session bootstrap, the hard-coded Alice/Acme and Bob/Globex account switcher, client construction, URL state, navigation, and component orchestration. The browser never chooses a tenant and never receives an upstream token.

Run the production build behind `@slatefs/demo-server`; direct Vite serving is useful for static layout only because `/api/v1/session` and `/api/*` are same-origin BFF routes. Query parameters support safe `volume`, `path`, `workspace`, `view`, and `ref` deep links and browser history.

Seed/reset orchestration remains a Phase 3 integration task. Any future reset script must use the running daemon/CLI and must not open a volume as a second writer.
