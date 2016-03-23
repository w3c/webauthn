.PHONY: force publish all bikeshed
all: index.html

LIBDIR ?= lib
include $(LIBDIR)/compat.mk
include $(LIBDIR)/config.mk
include $(LIBDIR)/id.mk
include $(LIBDIR)/ghpages.mk

setup_bikeshed:
	git clone --depth=1 --branch=master https://github.com/tabatkins/bikeshed.git ./bikeshed
	pip install pygments
	pip install --editable ./bikeshed
	bikeshed update

force:
	bikeshed -f spec ./index.src.html

index.html: index.src.html biblio.json
	bikeshed spec ./index.src.html
