# Documentation (Antora)

Run everything from this `docs/` directory.

## Setup
```sh
npm install --ignore-scripts
```

## Build the static site
```sh
npm run docs:build
```

## Preview locally
```sh
npm run docs:serve
```
`docs:serve` picks a free port automatically (`http-server` will print it).

## Project layout
- `antora-playbook.yml` — Antora site definition (sources, UI, output).
- `antora.yml` — component metadata (name/title/version/nav).
- `modules/ROOT/pages/` — pages.
- `modules/ROOT/nav.adoc` — navigation.
- `ui/ui-bundle.zip` — bundled Antora UI (kept locally for reliable builds).
- `build/` — generated site (ignored).

