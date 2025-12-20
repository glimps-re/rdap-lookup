FROM alpine
USER 1000:1000

COPY --chown=1000:1000 rdap-lookup /srv/rdap-lookup

RUN chmod +x /srv/rdap-lookup

ENTRYPOINT ["/srv/rdap-lookup"]
