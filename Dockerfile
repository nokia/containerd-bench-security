FROM alpine:3.13

LABEL \
  org.label-schema.name="containerd-security" \
  org.label-schema.url="https://https://scm.cci.nokia.net/bekefi/containerd-security" \
  org.label-schema.vcs-url="https://scm.cci.nokia.net/bekefi/containerd-security.git"

RUN apk add --no-cache iproute2 \
                       crictl \
                       dumb-init

COPY . /usr/local/bin/

HEALTHCHECK CMD exit 0

WORKDIR /usr/local/bin

ENTRYPOINT [ "/usr/bin/dumb-init", "containerd-bench-security.sh" ]
CMD [""]
