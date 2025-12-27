# Development container for ThreatExtract-IOC-NER
# Includes GPU support and development tools

FROM nvidia/cuda:12.4.1-cudnn-devel-ubuntu22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set Python environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

# Install system dependencies and development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-dev \
    python3.11-venv \
    python3-pip \
    git \
    curl \
    wget \
    vim \
    nano \
    htop \
    sudo \
    openssh-client \
    && ln -sf /usr/bin/python3.11 /usr/bin/python \
    && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/pip3 /usr/bin/pip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for VS Code
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Upgrade pip
RUN python -m pip install --upgrade pip setuptools wheel

# Copy requirements and install dependencies
COPY requirements.txt .

# Install PyTorch with CUDA support, then other dependencies
RUN pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124 \
    && pip install -r requirements.txt

# Install development tools
RUN pip install \
    pytest \
    pytest-cov \
    ruff \
    mypy \
    ipython \
    jupyterlab

# Create directories
RUN mkdir -p /workspace/data /workspace/output \
    && chown -R $USERNAME:$USERNAME /workspace

# Switch to non-root user
USER $USERNAME

# Set default shell to bash
ENV SHELL=/bin/bash

CMD ["bash"]
