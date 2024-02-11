FROM debian:12-slim
COPY ./polizei /polizei
ENTRYPOINT /polizei
