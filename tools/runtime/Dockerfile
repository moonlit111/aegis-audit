# All target execution uses a disposable, network-disabled container made from this image.
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm afl++ make binutils ca-certificates xz-utils dnsutils && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir semgrep==1.176.1
ADD --checksum=sha256:402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657 https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-amd64_linux.tar.xz /tmp/upx.tar.xz
RUN tar -xJf /tmp/upx.tar.xz -C /tmp && cp /tmp/upx-5.2.1-amd64_linux/upx /usr/local/bin/upx && rm -rf /tmp/upx*
RUN apt-get update && apt-get install -y --no-install-recommends libclang-rt-14-dev && rm -rf /var/lib/apt/lists/*
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SEMGREP_SEND_METRICS=off
WORKDIR /work
CMD ["python3", "--version"]
