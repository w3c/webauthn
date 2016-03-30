# Bikeshed Template Repository

The contents of this repository can be used to get started with a new bikeshed
document.

## Getting Started

You need a [GitHub account](https://github.com/join).

### New Draft Setup

[Make a new repository](https://github.com/new).  This guide will use the
name name `unicorn-protocol` here.

When prompted, select the option to initialize the repository with a README.

Clone that repository:
```sh
$ git clone https://github.com/unicorn-wg/unicorn-protocol.git
$ cd unicorn-protocol
```

Clone a copy of this respository into place:

```sh
$ git clone https://github.com/jcjones/bikeshed-template lib
```

Alternatively, you can use `git submodule` to get a stable version.

Creation of the bikeshed input file is currently unspecified, making this much
less slick than `[martinthomson/i-d-template](https://github.com/martinthomson/i-d-template)`.
Anyway, it should be `index.src.html` (currently).

Now, run the setup commands:
```sh
$ make -f lib/setup.mk
```

This removes adds some files, updates `README.md` with the details of your
draft, sets up a `gh-pages` branch for your editor's copy.

Check that everything looks OK, then push.
```sh
$ git push
```


### Updating The Editor's Copy

You can maintain `gh-pages` manually by running the following command
occasionally.

```sh
$ make ghpages
```

Or, you can setup an automatic commit hook using Travis or Circle CI.


### Automatic Update for Editor's Copy

This requires that you sign in with [Travis](https://travis-ci.org/) or
[Circle](https://circleci.com/).

First enable builds for the new repository:
[Travis](https://travis-ci.org/profile),
[Circle](https://circleci.com/add-projects).  Travis might need to be refreshed
before you can see your repository.

Then, you need to get yourself a [new GitHub application
token](https://github.com/settings/tokens/new).  The application token only
needs the `public_repo` privilege.  This will let it push updates to your
`gh-pages` branch.

You can add environment variables using the Travis or Circle interface.  Include
a variable with the name `GH_TOKEN` and the value of your newly-created
application token.  On Travis, make sure to leave the value of "Display value in
build log" disabled, or you will be making your token public.

**WARNING**: You might want to use a dummy account for application tokens to
minimize the consequences of accidental leaks of your key.

Once you enable pushes, be very careful merging pull requests that alter
`.travis.yml`, `circle.yml` or `Makefile`.  Those files can cause the value of
the token to be published for all to see.  You don't want that to happen.  Even
though tokens can be revoked easily, discovering a leak might take some time.
Only pushes to the main repository will be able to see the token, so don't worry
about pull requests.

As a side benefit, Travis and Circle will now also check pull requests for
errors, letting you know if things didn't work out so that you don't merge
anything suspect.


## Updating the Support Files

Occasionally improvements and changes are made to the Makefile or the
support files in this repository.  Just update the `lib/` directory with
`git pull`:

```sh
$ git -C lib pull origin master
```
