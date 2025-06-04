FROM mcr.microsoft.com/devcontainers/rust:latest

# Set the working directory
WORKDIR /workspace

# Install packages
RUN DEBIAN_FRONTEND="noninteractive" apt update && apt install -y gdb libpam0g libpam0g-dev nano openssh-server openssl pamtester protobuf-compiler sed

# Install Taskfile
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# TODO: Update the SSH config

# Setup an SSH key
RUN mkdir -p /home/vscode/.ssh
RUN ssh-keygen -a 100 -t ed25519 -f /home/vscode/.ssh/id_ed25519_non_default -N ""
RUN cat /home/vscode/.ssh/id_ed25519_non_default.pub > /home/vscode/.ssh/authorized_keys
RUN chown vscode:vscode -R /home/vscode/.ssh

# Fix directory creation bug
RUN service ssh start && service ssh stop
