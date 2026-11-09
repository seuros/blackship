# Blackship Technical Manual

The manual is a LaTeX book assembled from independent chapter files under
`chapters/`. Its cover is original vector artwork rendered by TikZ; no external
image assets are required.

On FreeBSD, install a complete TeX Live distribution and build with:

```sh
pkg install texlive-full
cd docs/manual
make
```

The result is `blackship-manual.pdf`. Run `make clean` to remove intermediate
files or `make distclean` to remove the PDF as well.

When behavior changes, update both the relevant chapter and the README. The CLI
and generated MCP manual remain authoritative for exact argument parsing.
