FROM python:alpine as builder

WORKDIR /email-oauth2-proxy

COPY requirements-no-gui.txt requirements-no-gui.txt
COPY emailproxy.py emailproxy.py

RUN	apk add curl busybox-extras binutils && \
	python -m pip install -r requirements-no-gui.txt && \
	pip install -U pyinstaller && \
	pyinstaller --onefile emailproxy.py

FROM alpine:3.16 as app-base
COPY --from=builder /email-oauth2-proxy/dist/emailproxy /usr/local/bin/emailproxy
ENTRYPOINT ["/usr/local/bin/emailproxy", "--no-gui", "--local-server-auth"]
CMD ["--config-file=/etc/emailproxy.config"]
