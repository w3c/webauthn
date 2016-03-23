## Identify drafts, types and versions

ifneq (,$(shell git submodule status $(LIBDIR) 2>/dev/null))
SUBMODULE = true
endif

# CI config
CI ?= false
CI_BRANCH = $(TRAVIS_BRANCH)$(CIRCLE_BRANCH)
CI_USER = $(word 1,$(subst /, ,$(TRAVIS_REPO_SLUG)))$(CIRCLE_PROJECT_USERNAME)
CI_REPO = $(word 2,$(subst /, ,$(TRAVIS_REPO_SLUG)))$(CIRCLE_PROJECT_REPONAME)
ifeq (true,$(CI))
CI_REPO_FULL = $(CI_USER)/$(CI_REPO)
endif
CI_IS_PR = $(if $(CI_PULL_REQUESTS),true,$(if $(TRAVIS_PULL_REQUEST),$(TRAVIS_PULL_REQUEST),false))

# Github guesses
ifndef CI_REPO_FULL
GITHUB_REPO_FULL := $(shell git ls-remote --get-url | sed -e 's/^.*github\.com.//;s/\.git$$//')
GITHUB_USER := $(word 1,$(subst /, ,$(GITHUB_REPO_FULL)))
GITHUB_REPO := $(word 2,$(subst /, ,$(GITHUB_REPO_FULL)))
else
GITHUB_REPO_FULL := $(CI_REPO_FULL)
GITHUB_USER := $(CI_USER)
GITHUB_REPO:= $(CI_REPO)
endif
