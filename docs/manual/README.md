# Blackship Technical Manual

LaTeX sources for the manual: one file per chapter under `chapters/`, with
cover artwork in `assets/`. The PDF is not committed — the release workflow
builds it and attaches `blackship-manual.pdf` to every GitHub release.

To build locally you need TeX Live with `latexmk`:

```sh
cd docs/manual
make            # produces blackship-manual.pdf
make clean      # drops intermediates
make distclean  # drops the PDF too
```

release-please bumps `\BlackshipVersion` in `blackship-manual.tex`, so don't
edit it by hand. When behavior changes, update the relevant chapter along with
the README. The CLI and the generated MCP manual remain authoritative for exact
argument parsing.
