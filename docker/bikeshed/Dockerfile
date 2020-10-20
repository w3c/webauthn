FROM python:3.8

VOLUME /spec
WORKDIR /spec

RUN pip install bikeshed
RUN bikeshed update

ENTRYPOINT ["/usr/local/bin/bikeshed", "--print=console"]
CMD ["spec"]
