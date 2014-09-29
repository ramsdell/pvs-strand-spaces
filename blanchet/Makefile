CPSAFLAGS = +RTS -M512m -RTS
SRCS := $(wildcard *.scm) $(wildcard *.lsp)
include ../cpsa.mk

all:    $(SRCS:%.scm=%_shapes.xhtml) $(SRCS:%.scm=%_logic.text) \
        $(SRCS:%.lsp=%_shapes.xhtml) $(SRCS:%.lsp=%_logic.text)

clean:
	-rm *.txt *.xhtml *.text
