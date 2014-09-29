# Creates a PVS Strand Spaces release.
# To use type make dist.

NAME = pvs-strand-spaces

dist:
	DATE=`date --iso`; \
	find . -name .git -prune -o -print0 \
		| cpio -pmd0 ../$(NAME)-$${DATE}; \
	cd ..; \
	tar czf $(NAME)-$${DATE}.tar.gz $(NAME)-$${DATE}; \
	rm -rf $(NAME)-$${DATE}
