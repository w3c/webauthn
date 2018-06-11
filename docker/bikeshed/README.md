Docker image with `bikeshed`
===

This requires having [Docker][docker] installed.

Build the image:

    alice@work $ docker build -t bikeshed docker/bikeshed --no-cache

Then run it as `bikeshed` or `bikeshed watch`:

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


[docker]: https://www.docker.com/community-edition
