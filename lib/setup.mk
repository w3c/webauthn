.PHONY: setup
setup: setup-ghpages

GIT_ORIG := $(shell git branch | grep '*' | cut -c 3-)
ifneq (1,$(words $(GIT_ORIG)))
$(error Unable to work from non-branch: $(GIT_ORIG))
endif

.PHONY: setup-ghpages
setup-ghpages:
# Abort if there are local changes
	@test `git status -s | wc -l` -eq 0 || \
	  ! echo "Error: Uncommitted changes on branch"
	@git remote show -n origin >/dev/null 2>&1 || \
	  ! echo "Error: No remote named 'origin' configured"
# Check if the gh-pages branch already exists locally
	@if git show-ref refs/heads/gh-pages >/dev/null 2>&1; then \
	  ! echo "Error: gh-pages branch already exists"; \
	else true; fi
# Check if the gh-pages branch already exists on origin
	@if git show-ref origin/gh-pages >/dev/null 2>&1; then \
	  echo 'Warning: gh-pages already present on the origin'; \
	  git branch gh-pages origin/gh-pages; false; \
	else true; fi
	@echo "Initializing gh-pages branch"
	git checkout --orphan gh-pages
	git rm -rf .
	touch index.html
	echo 'general:' >circle.yml
	echo '  branches:' >>circle.yml
	echo '    ignore:' >>circle.yml
	echo '      - gh-pages' >>circle.yml
	git add index.html circle.yml
	git commit -m "Automatic setup of gh-pages."
	git push --set-upstream origin gh-pages
	git checkout -qf "$(GIT_ORIG)"
	git clean -qfdX
