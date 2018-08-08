FROM python:2

VOLUME /spec
WORKDIR /spec

RUN git clone --depth=1 --branch=master https://github.com/tabatkins/bikeshed.git /bikeshed
RUN pip install --editable /bikeshed
RUN bikeshed update

ENTRYPOINT ["/usr/local/bin/bikeshed", "--print=console"]
CMD ["spec"]
