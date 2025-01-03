# PAM OAuth PAM module

[![Release Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/release.yml?label=Release&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/release.yml)
[![Security Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/security.yml?label=Security&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/security.yml)

A Pluggable Authentication Module (PAM) and Name Service Switch (NSS) module for OAuth/OpenID Connect (OIDC).

> [!WARNING]  
> This project is under active development and is not yet ready for production use.

## Documentation

### Architecture

The easiest way to understand the architecture of this project is to walk through a typical authentication flow. For the sake of example, let's assume that the user is trying to SSH into a server named `prod.example.com`, which is running the PAM OAuth PAM module and is configured to connect to the PAM OAuth server running at `pam-oauth.example.com`.

1. The user initiates an SSH connection to `prod.example.com`.
   1. If the user doesn't already have an account on `prod.example.com`, the PAM OAuth NSS module (on `prod.example.com`) will return a stub account to the PAM stack. The stub account is configured to use the PAM OAuth login shell. <sup>[1](#footnotes)</sup>
   2. The SSH server (on `prod.example.com`) invokes the PAM stack to authenticate the user. <sup>[2](#footnotes)</sup>
      1. The PAM stack invokes the PAM OAuth PAM module (on `prod.example.com`) in `issue` mode.
         1. The PAM OAuth PAM module (on `prod.example.com`) contacts the PAM OAuth server (on `pam-oauth.example.com`) to issue a challenge.
         2. The PAM OAuth server (on `pam-oauth.example.com`) issues a challenge, returning the challenge URL back to the PAM OAuth PAM module (on `prod.example.com`).
         3. The PAM OAuth PAM module (on `prod.example.com`) prints the challenge URL to the user's terminal.
      2. The PAM stack invokes the PAM OAuth PAM module (on `prod.example.com`) again in `verify` mode. <sup>[2](#footnotes)</sup>
         1. The PAM OAuth PAM module (on `prod.example.com`) waits for the user to visit the URL.
2. The user visits the challenge URL in their browser
   1. The PAM OAuth server (on `pam-oauth.example.com`) initiates an OAuth2/OIDC authorization code flow, redirecting the user to the configured identity provider.
   2. The user authenticates with the identity provider.
   3. The identity provider redirects the user back to the PAM OAuth server (on `pam-oauth.example.com`).
   4. The PAM OAuth server (on `pam-oauth.example.com`) exchanges the authorization code for an access token, validates the OAuth ID token (if configured to do so), runs the hook script (to map the OAuth tokens to the format expected by the PAM OAuth server), and notifies the PAM OAuth PAM module (on `prod.example.com`) that the user has authenticated.
3. The PAM OAuth PAM module (on `prod.example.com`) allows the user to pass.
   1. If the PAM OAuth NSS module (on `prod.example.com`) returned a stub account to the PAM stack (as opposed to a normal account on `prod.example.com` in step 1), the PAM OAuth login shell (on `prod.example.com`) will run (instead of a normal login shell).
   2. The PAM OAuth login shell (on `prod.example.com`) will create the user's account on `prod.example.com` and execute the user's actual login shell.

#### Footnotes

1. This is a workaround to prevent the PAM stack from always rejecting the user if they don't already have an account on the computer they are trying to access. This allows users to have a seamless experience when logging into a server for the first time (otherwise they would have to log in once to create the account and then log in again to actually use the account).
2. The PAM module is invoked twice to workaround [this limitation](https://bugzilla.mindrot.org/show_bug.cgi?id=2876) in OpenSSH, where non-interactive messages are not flushed to the user's terminal. Credit to [Sorah Fukumori](https://github.com/sorah/clarion/tree/master/examples/pam-u2f) for this workaround.

### Structure

- `api/`: Shared gRPC API definitions
- `creates/`: Rust crates
  - `login/`: Login shell (Client)
  - `server/`: Server (Server)
  - `pam/`: PAM module (Client)
  - `nss/`: NSS module (Client)
- `pkg/`: Package scripts, configurations, and other resources
  - `init/`: Systemd service files
  - `scripts/`: Post-installation/pre-removal scripts
  - `nfpm-client.yml`: [NFPM](https://nfpm.goreleaser.com/) client package configuration
  - `nfpm-server.yml`: [NFPM](https://nfpm.goreleaser.com/) server package configuration

### Development

1. Start the [Devcontainer](https://containers.dev) ([`.devcontainer`](.devcontainer))
2. Build everything:

   ```shell
   task build
   ```

3. Start the server:

   ```shell
   # TODO
   ```

4. Attempt to authenticate:

   ```shell
   pamtester login $USER authenticate
   ```
