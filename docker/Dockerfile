# Extend CTFd's official image with the edo plugin baked in.
#
# Build context is the REPO ROOT (see `build:` in docker-compose.yml). The
# .dockerignore at the repo root excludes docker/ and daemon/ so those don't
# get shipped inside the plugin folder.
#
# Pin the CTFd tag to a known-good release rather than :latest — plugins are
# sensitive to CTFd internals.
FROM ctfd/ctfd:3.7.5

USER root

# Copy the plugin sources into CTFd's plugins directory. Folder name MUST be
# `edo_plugin` (underscore) because CTFd imports it as a Python module.
COPY --chown=1001:1001 . /opt/CTFd/CTFd/plugins/edo_plugin/

# Install plugin Python deps into the image so APScheduler is available at
# import time. CTFd's requirements are already installed by the base image.
RUN pip install --no-cache-dir -r /opt/CTFd/CTFd/plugins/edo_plugin/requirements.txt

USER 1001
