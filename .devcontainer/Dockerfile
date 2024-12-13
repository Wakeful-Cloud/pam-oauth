FROM mcr.microsoft.com/devcontainers/rust:latest

# Set the working directory
WORKDIR /workspace

# Install packages
RUN DEBIAN_FRONTEND="noninteractive" apt update && apt install -y libpam0g libpam0g-dev nano openssh-server openssl pamtester sed

# Install Taskfile
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Update PAM config
RUN sed -i -e 's/auth	\[success=1 default=ignore\]	pam_unix\.so nullok/auth	[success=2 default=ignore]	pam_unix.so nullok\nauth	[success=1 default=ignore]	pam_oauth.so/' /etc/pam.d/common-auth