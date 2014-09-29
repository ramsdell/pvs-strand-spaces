CPSAFLAGS = +RTS -M512m -RTS

SRCS := $(wildcard *.scm)

include ../cpsa.mk

all:    $(SRCS:%.scm=%_shapes.xhtml) $(SRCS:%.scm=%.xhtml) \
        $(SRCS:%.scm=%_logic.text)

clean:
	-rm *.txt *.xhtml
