# Multi-stage build: compile the workspace, install via the real
# Makefile path so the image layout matches `make install` exactly,
# then copy that stage into a slim runtime.
FROM rust:1.88-bookworm AS builder

WORKDIR /src
COPY . .

# `install -o lp` in the Makefile requires the lp user to exist.
RUN id lp >/dev/null 2>&1 \
 || useradd --system --no-create-home --shell /usr/sbin/nologin lp; \
 make install DESTDIR=/stage

FROM debian:bookworm-slim

RUN id lp >/dev/null 2>&1 || { \
      groupadd --system lp 2>/dev/null; \
      useradd --system --gid lp --no-create-home \
        --shell /usr/sbin/nologin lp; }; \
    groupadd --system lpadmin 2>/dev/null; \
    mkdir -p /etc/cups /var/spool/cups /var/log/cups /run/cups; \
    chown lp:lp /var/spool/cups /var/log/cups /run/cups

COPY --from=builder /stage /

# Inside a container, port publishing arrives on eth0 - loopback-only
# listening would make -p 631:631 unreachable. Interface exposure is
# controlled by the publish flag, so 0.0.0.0 is correct here.
RUN sed -i 's/^Listen localhost:631/Listen 0.0.0.0:631/' /etc/cups/cupsd.conf

EXPOSE 631
VOLUME ["/etc/cups", "/var/spool/cups", "/var/log/cups"]

# Port 631 is privileged, so the daemon must start as root; it drops
# to User lp / Group lp itself per cups-files.conf.
ENTRYPOINT ["/usr/sbin/cupsd", "-f"]
