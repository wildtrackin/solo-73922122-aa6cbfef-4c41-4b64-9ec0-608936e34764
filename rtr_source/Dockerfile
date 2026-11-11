FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RTR_SERVER_PORT=8210 \
    CONTROL_PORT=8211 \
    EXPIRE_INTERVAL=7200

WORKDIR /app

COPY rtr_source ./rtr_source

RUN addgroup --system rtr \
    && adduser --system --ingroup rtr --no-create-home rtr \
    && chown -R rtr:rtr /app

USER rtr

EXPOSE 8210 8211

# 容器内健康检查：控制口返回当前状态即视为存活。
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8211/state', timeout=5).read()"

CMD ["python", "-m", "rtr_source.server"]
