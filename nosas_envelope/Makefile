CPSAFLAGS = +RTS -M512m -RTS
SRCS := $(wildcard *.scm) $(wildcard *.lsp)
include ../cpsa.mk

all:    $(SRCS:%.scm=%.xhtml) $(SRCS:%.lsp=%.xhtml) \
        $(SRCS:%.scm=%_shapes.xhtml) $(SRCS:%.lsp=%_shapes.xhtml)

clean:
	-rm *.txt *.xhtml *.text
