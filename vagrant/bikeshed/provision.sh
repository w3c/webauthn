#! /usr/bin/env bash

sudo apt-get update -qq
sudo apt-get install -qq python python-pip python-pygments

git clone --depth=1 --branch=master https://github.com/tabatkins/bikeshed.git /vagrant/bikeshed
pip install --editable /vagrant/bikeshed
cp -R /vagrant/.spec-data/* /vagrant/bikeshed/bikeshed/spec-data/
