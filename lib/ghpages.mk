## Update the gh-pages branch with useful files

GHPAGES_TMP := /tmp/ghpages$(shell echo $$$$)
.INTERMEDIATE: $(GHPAGES_TMP)
ifneq (,$(CI_BRANCH))
SOURCE_BRANCH := $(CI_BRANCH)
else
SOURCE_BRANCH := $(shell git branch | grep '*' | cut -c 3-)
endif
ifneq (,$(findstring detached from,$(SOURCE_BRANCH)))
SOURCE_BRANCH := $(shell git show -s --format='format:%H')
endif

TARGET_DIR := $(filter-out master/,$(SOURCE_BRANCH)/)
PUSH_GHPAGES_BRANCHES ?= true

# Don't upload if we are on CI and this is a PR
ifeq (true true,$(CI) $(CI_IS_PR))
PUSH_GHPAGES := false
else
# Otherwise, respect the value of PUSH_GHPAGES_BRANCHES
ifeq (false,$(PUSH_GHPAGES_BRANCHES))
PUSH_GHPAGES := $(if $(TARGET_DIR),false,true)
else
PUSH_GHPAGES := true
endif
endif

.PHONY: ghpages
ghpages: index.html img
ifneq (true,$(CI))
	@git show-ref refs/heads/gh-pages >/dev/null 2>&1 || \
	  (git show-ref refs/remotes/origin/gh-pages >/dev/null 2>&1 && \
	    git branch -t gh-pages origin/gh-pages) || \
	  ! echo 'Error: No gh-pages branch, run `make -f lib/setup.mk` to initialize it.'
endif
ifeq (true,$(PUSH_GHPAGES))
	mkdir $(GHPAGES_TMP)
	cp -R $^ $(GHPAGES_TMP)
	git clean -qfdX
ifeq (true,$(CI))
	git config user.email "ci-bot@example.com"
	git config user.name "CI Bot"
	git checkout -q --orphan gh-pages
	git rm -qr --cached .
	git clean -qfd
	git pull -qf origin gh-pages
else
	git checkout gh-pages
	git pull
endif
ifneq (,$(TARGET_DIR))
	mkdir -p $(CURDIR)/$(TARGET_DIR)
endif
	cp -R $(GHPAGES_TMP)/* $(CURDIR)/$(TARGET_DIR)
	git add -f $(addprefix $(TARGET_DIR),$^)
	if test `git status --porcelain | grep '^[A-Z]' | wc -l` -gt 0; then \
	  git commit -m "Script updating gh-pages. [ci skip]"; fi
ifneq (,$(CI_HAS_WRITE_KEY))
	git push https://github.com/$(CI_REPO_FULL).git gh-pages
else
ifneq (,$(GH_TOKEN))
	@echo git push -q https://github.com/$(CI_REPO_FULL).git gh-pages
	@git push -q https://$(GH_TOKEN)@github.com/$(CI_REPO_FULL).git gh-pages >/dev/null 2>&1
endif
endif
	-git checkout -qf "$(SOURCE_BRANCH)"
	-rm -rf $(GHPAGES_TMP)
endif # PUSH_GHPAGES
