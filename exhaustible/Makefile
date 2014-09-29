CPSAFLAGS = +RTS -M512m -RTS
SRCS := $(wildcard *.scm) $(wildcard *.lsp)
include ../cpsa.mk

all:    $(SRCS:%.scm=%_shapes.xhtml) $(SRCS:%.scm=%_logic.text) \
        $(SRCS:%.scm=%.xhtml)

clean:
	-rm *.txt *.xhtml *.text
