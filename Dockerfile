FROM python:3.7-slim-buster
COPY zzz.py /usr/bin
ENTRYPOINT ["/usr/bin/zzz.py"]
VOLUME /data
