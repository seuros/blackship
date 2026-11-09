LATEXMK ?= latexmk
MAIN = blackship-manual.tex
PDF = blackship-manual.pdf
CHAPTERS != find chapters -type f -name '*.tex' -print

.PHONY: all clean distclean

all: $(PDF)

$(PDF): $(MAIN) blackship-style.tex cover.tex frontmatter.tex assets/blackship-cover.jpg $(CHAPTERS)
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error $(MAIN)

clean:
	$(LATEXMK) -c $(MAIN)

distclean:
	$(LATEXMK) -C $(MAIN)
