FROM python:2

LABEL version="0.0.1" \
  maintainer="CJ Barker" \
  maintainer.email="cjbarker@gmail.com" \
  description="Builds Generic Docker image for Pyhack (Python) Development" \
  repository="https://gitlab.com/cjbarker/pyhack"

# Install packages
RUN apt update \
    && apt upgrade -y

# Install & configure pipenv
RUN pip install pipenv

# install app into container
RUN set -ex && mkdir /app

WORKDIR /app

# Add Pipfiles
COPY Pipfile Pipfile
COPY Pipfile.lock Pipfile.lock

# Install Python module dependencies
RUN set -ex && pipenv install --deploy --system
