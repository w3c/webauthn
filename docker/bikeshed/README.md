Docker image with `bikeshed`
===

Build the image:

    alice@work $ cd webauthn/docker/bikeshed
    alice@work $ docker build -t bikeshed . --no-cache
    alice@work $ cd ../..

Then run it as `bikeshed` or `bikeshed watch`:

- ```
  alice@work $ docker run --name bikeshed-webauthn -it --volume $(pwd):/spec bikeshed
  alice@work $ docker start --attach bikeshed-webauthn
  ```

- ```
  alice@work $ docker run --name bikeshed-webauthn-watch -it --volume $(pwd):/spec bikeshed watch
  ==============DONE==============
  ^C
  alice@work $ docker start --attach bikeshed-webauthn-watch
  ==============DONE==============
  ^C
  alice@work $ docker stop bikeshed-webauthn-watch
  ```
