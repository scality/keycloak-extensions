ARG TAG=26.2.0

FROM quay.io/keycloak/keycloak:${TAG}

ENV KEYCLOAK_DIR /opt/keycloak
ENV KC_PROXY edge

LABEL maintainer="Jean-Baptiste, Watenberg <jean-baptiste.watenberg@scality.com>"

USER 0

COPY target/keycloak-extensions.jar $KEYCLOAK_DIR/providers/keycloak-extensions.jar

RUN $KEYCLOAK_DIR/bin/kc.sh build --spi-hostname-provider=default

USER 1000
