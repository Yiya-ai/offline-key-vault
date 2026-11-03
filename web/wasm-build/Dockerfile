# This context contains public build inputs only. Never use the repository as context.
FROM python:3.14.2-bookworm@sha256:bee107ebb973b658218ed57303beb7a8fd9f187dd574a740bc62bc88ea39b629 AS builder
ENV PYODIDE_XBUILDENV_PATH=/opt/pyodide-cross \
    PATH=/root/.cargo/bin:$PATH \
    SOURCE_DATE_EPOCH=1790985600
RUN python -m pip install --no-cache-dir pyodide-build==0.39.3
RUN pyodide xbuildenv install 314.0.7 && pyodide xbuildenv install-emscripten
RUN curl --fail --location --retry 3 https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init -o /tmp/rustup-init \
    && curl --fail --location --retry 3 https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init.sha256 -o /tmp/rustup-init.sha256 \
    && cd /tmp && sha256sum -c rustup-init.sha256 \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --profile minimal --default-toolchain "$(pyodide config get rust_toolchain)" \
    && rustup target add wasm32-unknown-emscripten
WORKDIR /build
COPY sources.json fetch_sources.py build.sh build-constraints.txt ./
ENV PIP_CONSTRAINT=/build/build-constraints.txt
RUN python fetch_sources.py
RUN bash build.sh
FROM scratch AS artifact
COPY --from=builder /output/ /output/
# Extraction-only image: build_wasm.py creates it but never starts it.
CMD ["artifact-only"]
