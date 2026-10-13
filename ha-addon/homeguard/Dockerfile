FROM python:3.12-alpine

LABEL io.hass.type="addon" io.hass.version="1.0.0"

RUN apk add --no-cache tzdata

ENV PYTHONUNBUFFERED=1 \
    HOMEGUARD_CONFIG=/data/config.json

WORKDIR /data
COPY app/ /app/

RUN chmod +x /app/run.sh

CMD ["/app/run.sh"]