Docker image with `bikeshed`
===

This requires having [Docker][docker] installed.

Build the image:

    alice@work $ docker build -t bikeshed docker/bikeshed --no-cache

Then run it as `bikeshed` or `bikeshed watch`. Use the `docker run` command the
first time you run the image after building it, then the `docker start` command
on subsequent uses.

- Either in one-shot mode:

  ```
  alice@work $ docker run --name bikeshed-webauthn -it --volume $(pwd):/spec bikeshed
  alice@work $ docker start --attach bikeshed-webauthn
  alice@work $ $BROWSER index.html
  ```

- Or in continuous watch mode:

  ```
  alice@work $ docker run --name bikeshed-webauthn-watch -it --volume $(pwd):/spec bikeshed watch
  ==============DONE==============
  ^C
  alice@work $ docker start --attach bikeshed-webauthn-watch
  ==============DONE==============
  ^C
  alice@work $ docker stop bikeshed-webauthn-watch
  ```


Rebuilding
---

To rebuild the image with the latest Bikeshed version, run `docker build` again:

    alice@work $ docker build -t bikeshed docker/bikeshed --no-cache

This will create a new image and overwrite the `bikeshed` tag, but any existing
container(s) will still be of the previous version of the image (which now no
longer has a tag).

So delete the existing container(s):

    alice@work $ docker rm -v bikeshed-webauthn
    alice@work $ docker rm -v bikeshed-webauthn-watch

...and then re-run the `docker run` command(s) in the previous section.


[docker]: https://www.docker.com/community-edition
