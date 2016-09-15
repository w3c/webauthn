#!/bin/bash
set -ev
STATUS=`git log -1 --pretty=oneline`

rm -rf out
mkdir out
cp index.html ./out/
mkdir ./out/images
cp images/* ./out/images

cd out
git init
git config user.name "Travis-CI"
git config user.email "travis-ci"
ls
git add .
git commit -m "Built by Travis-CI: ${STATUS}"
git status

GH_REPO="@github.com/${TRAVIS_REPO_SLUG}.git"
FULL_REPO="https://${GH_TOKEN}${GH_REPO}"
git push --force --quiet $FULL_REPO master:gh-pages
