# Documentation (Antora)

This directory contains the [Antora-based documentation](https://docs.antora.org/antora/latest/) site for the Keycloak OID4VP plugin. The documentation is written in AsciiDoc and generated into a static HTML site.

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

## Project layout

- `antora-playbook.yml` — Antora site definition (sources, UI, output).
- `antora.yml` — component metadata (name/title/version/nav).
- `modules/ROOT/pages/` — pages.
- `modules/ROOT/nav.adoc` — navigation.
- `ui/ui-bundle.zip` — bundled Antora UI (kept locally for reliable builds).
