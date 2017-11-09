Vagrant VM with `bikeshed`
===

Usage:

    alice@work $ cd webauthn/vagrant/bikeshed
    alice@work $ vagrant up
    alice@work $ vagrant ssh
    ubuntu@ubuntu-xenial $ cd /vagrant
    ubuntu@ubuntu-xenial $ bikeshed spec
    ubuntu@ubuntu-xenial $ exit
    alice@work $ $BROWSER ../../index.html
    alice@work $ vagrant destroy
