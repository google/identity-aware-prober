# This dockerfile is never executed directly. It is used to provide the
# iaprober binary to the Cloudprober container, hence the ENTRYPOINT
# is not normally used other than for testing the container.

FROM alpine:3.7
COPY iaprober /
ENTRYPOINT ["/bin/sh"]

