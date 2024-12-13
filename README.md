# PAM OAuth Module

[![Release Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/release.yml?label=Release&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/release.yml)
[![Security Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/security.yml?label=Security&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/security.yml)

A Pluggable Authentication Module (PAM) and Name Service Switch (NSS) module for OAuth/OpenID Connect (OIDC).

> [!WARNING]  
> This project is under active development and is not yet ready for production use.

## Documentation

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
