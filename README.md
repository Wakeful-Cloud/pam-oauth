# PAM OAuth Module

[![Release Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/release.yml?label=Release&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/release.yml)
[![Security Status](https://img.shields.io/github/actions/workflow/status/wakeful-cloud/pam-oauth/security.yml?label=Security&style=flat-square)](https://github.com/wakeful-cloud/pam-oauth/actions/workflows/security.yml)

A Pluggable Authentication Module (PAM) and optional Name Service Switch (NSS) for OAuth, with optional support for OpenID Connect (OIDC).

> [!WARNING]  
> This project is under active development and is not yet ready for production use.

## Documentation

### Setup

1. Download the latest release from the [releases page](https://github.com/wakeful-cloud/pam-oauth/releases)
2. Extract/install the client on the client machine and the server on the server machine, for example:

```bash
VERSION="X.Y.Z" # Get the latest semantic version (Without the "v" prefix!) from the releases page

# Debian/Ubuntu
wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-client_${VERSION}_amd64.deb
sudo dpkg -i pam-oauth-client_${VERSION}_amd64.deb

wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-server_${VERSION}_amd64.deb
sudo dpkg -i pam-oauth-server_${VERSION}_amd64.deb

# Red Hat/CentOS
wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-client-${VERSION}-1.x86_64.rpm
sudo rpm -i pam-oauth-client-${VERSION}-1.x86_64.rpm

wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-server-${VERSION}-1.x86_64.rpm
sudo rpm -i pam-oauth-server-${VERSION}-1.x86_64.rpm

# Arch Linux
wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-client-${VERSION}-1-x86_64.pkg.tar.zst
sudo pacman -U pam-oauth-client-${VERSION}-1-x86_64.pkg.tar.zst

wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-server-${VERSION}-1-x86_64.pkg.tar.zst
sudo pacman -U pam-oauth-server-${VERSION}-1-x86_64.pkg.tar.zst

# Alpine Linux
wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-client_${VERSION}_x86_64.apk
sudo apk add pam-oauth-client_${VERSION}_x86_64.apk

wget -q https://github.com/Wakeful-Cloud/pam-oauth/releases/download/v${VERSION}/pam-oauth-server_${VERSION}_x86_64.apk
sudo apk add pam-oauth-server_${VERSION}_x86_64.apk
```

3. Initialize the server:

```bash
# You will likely want to add the following flags so that clients can verify the server's TLS certificate in the future:
# --server-common-name=hostname --server-dns-san=localhost --server-dns-san=<server hostname> --server-ip-san=127.0.0.1 --server-ip-san=::1 --server-ip-san=<server external IP>
sudo pam-oauth-server initialize
```

4. Update the server configuration (e.g.: OAuth provider's details, listening address) in `/etc/pam-oauth/server.toml`

5. Add a client:

```bash
# You will likely want to add the following flags so that the server can verify the client's TLS certificate in the future:
# --client-dns-san=<client hostname> --client-ip-san=<client external IP>
sudo pam-oauth-server client add --client-common-name=<client hostname> --client-cert=<path to client certificate> --client-key=<path to client key>
```

6. Initialize the client:

```bash
sudo pam-oauth-client initialize
```

7. Update the client configuration (e.g.: server's address) in `/etc/pam-oauth/client.toml`

8. Start the server:

```bash
# If using systemd
sudo systemctl start pam-oauth-server

# Or manually
sudo pam-oauth-server serve
```

9. Update the PAM configuration (e.g.: `/etc/pam.d/sshd`):

```diff
+ auth sufficient pam_oauth.so /usr/bin/pam-oauth-client --config /etc/pam-oauth/client.toml run

# All other auth rules
@include common-auth
```

_Note: the `sufficient` keyword means that if this module succeeds, the rest of the `auth` stack (i.e.: password or key-based authentication) will be skipped._

10. Update the NSS configuration (e.g.: `/etc/nsswitch.conf`):

```diff
- passwd: files systemd
- group: files systemd
+ passwd: files systemd oauth
+ group: files systemd oauth
```

11. Update the SSH server configuration (e.g.: `/etc/ssh/sshd_config`):

```diff
- KbdInteractiveAuthentication no
- UsePAM no
+ KbdInteractiveAuthentication yes
+ UsePAM yes
```

12. Restart the SSH server:

```bash
sudo systemctl restart sshd
```

### Client Configuration

#### Prompt Message

The prompt message template is a [Go text template](https://pkg.go.dev/text/template) which is used to generate the message to prompt the user to open the authentication URL. The following variables are available:

- `.Username`: the username of the user attempting to authenticate
- `.Url`: the authentication URL

#### Create User Command

The create user command is a [shell command](https://github.com/mvdan/sh) which is used to create a user. The environment variables that are passed to the command are determined by the [callback expression](#callback-expression) along with the following:

- `PAM_OAUTH_USERNAME`: the username of the user attempting to authenticate

### Server Configuration

#### Callback Expression

The callback expression is an [Expr](https://expr-lang.org) (Domain-Specific Language/DSL) expression which must:

- Verify that the username of the user attempting to authenticate matches the username of the user who authenticated with the OAuth provider
- Verify that the user is authorized to use PAM OAuth
- Return any and all variables that are required by the create user command

##### Variables

The following variables are passed to the callback expression:

- `username: string`: the username of the user attempting to authenticate
- `accessToken: string`: the raw access token
- `refreshToken: string`: the raw refresh token
- `oauthToken: struct`: the OAuth token returned by the OAuth provider
  - `expiry: time.Time`: the expiry time of the token
  - `type: string`: the type of the token
- `idToken: struct | nil`: the ID token returned by the OIDC provider (Only if the `oidc_url` is set in the OAuth client configuration)
  - `accessTokenHash: string`: the access token hash
  - `audience: []string`: the audience of the token
  - `claims: map[string]any`: the claims of the token
  - `expiry: time.Time`: the expiry time of the token
  - `issuedAt: time.Time`: the time the token was issued
  - `issuer: string`: the issuer of the token
  - `nonce: string`: the nonce of the token
  - `raw: string`: the raw token
  - `subject: string`: the subject of the token

##### Return Values

The following return values are expected to be returned by the callback expression:

- `ok: bool`: whether or not to allow the user to authenticate
- `message: string`: the message to show to the user if rejected
- `env: map[string]string`: the environment variables to pass to the create user command running on the client (Note that `PAM_OAUTH_USERNAME` is always passed to the create user command)

##### Functions

The following functions are available in the callback expression:

- Email address utilities
  - `parseEmail`: parses an email address into its name and domain
    - Parameters:
      - `string`: the email address (e.g.: `<Name> username@example.com`)
    - Returns:
      - `struct`
        - `ok: bool`: whether the email address is valid
        - `name: string | nil`: the name part of the email address (e.g.: `Name`), if `ok` is `true` and present
        - `local: string`: the local part of the email address (e.g.: `username`), if `ok` is `true`
        - `domain: string`: the domain part of the email address (e.g.: `example.com`), if `ok` is `true`
- JSON Web Token (JWT) utilities
  - `parseJwt`: decodes a JWT and returns the claims
    - Parameters:
      - `string`: the JWT
      - `string`: the secret key
    - Returns:
      - `struct`
        - `ok: bool`: whether the token is valid (e.g.: not expired, signed with the provided secret, etc.)
        - `header: map[string]any | nil`: the header, if `ok` is `true`
        - `claims: map[string]any | nil`: the claims, if `ok` is `true`
- Regular Expression (RegEx) utilities
  - `execRegex`: executes an RE2 regular expression and returns the first match's capturing groups
    - Parameters:
      - `string`: the regular expression pattern
      - `string`: the input string
    - Returns:
      - `[]string`: the capturing groups (Including the full match as the first element)
  - `execRegexAll`: executes an RE2 regular expression and returns all matches' capturing groups
    - Parameters:
      - `string`: the regular expression pattern
      - `string`: the input string
    - Returns:
      - `[][]string`: the capturing groups (Including the full match as the first element of each match)
  - `replaceRegex`: replaces first occurrences of a regular expression pattern with a replacement string
    - Parameters:
      - `string`: the regular expression pattern
      - `string`: the input string
      - `replacement: string`: the replacement string
    - Returns:
      - `string`: the input string with all occurrences of the pattern replaced with the replacement string
  - `replaceRegexAll`: replaces all occurrences of a regular expression pattern with a replacement string
    - Parameters:
      - `string`: the regular expression pattern
      - `string`: the input string
      - `string`: the replacement string
    - Returns:
      - `string`: the input string with all occurrences of the pattern replaced with the replacement string
- Miscellaneous utilities
  - `log`: logs a message to the server log
    - Parameters:
      - `string`: the log level (One of `DEBUG`, `INFO`, `WARN`, or `ERROR`)
      - `string`: the message to log

##### Examples

###### 1. Simple verification

```javascript
// Get the email from the ID token
let email = idToken?.claims?.email;

// Assertions
let emailOk = email != nil;
let usernameOk = email == username;

// Return
!emailOk
  ? {
      ok: false,
      message: "Your email address is invalid",
      env: {},
    }
  : !usernameOk
  ? {
      ok: false,
      message: "Your username does not match your email address",
      env: {},
    }
  : {
      ok: true,
      message: "",
      env: {
        "COMMENT": email
      },
    }
```

_Note: this expression will still allow anyone who succesfully authenticates with the OAuth provider to authenticate with PAM OAuth. Furthermore, users must connect using their full email address when using SSH (e.g.: `ssh username@mail.example.com@ssh.example.com`) ._

###### 2. Domain-restricted verification

```javascript
// Settings
let allowedDomains = ["mail.example.com"];
let allowedUsers = ["user1"];

// Get the email from the ID token
let email = idToken?.claims?.email;

// Parse the email
let parsedEmail = email != nil ? parseEmail(email) : nil;

// Assertions
let emailOk = parsedEmail != nil && parsedEmail.ok;
let emailDomainOk = parsedEmail?.domain in allowedDomains;
let emailLocalOk = parsedEmail?.local == username;
let usernameOk = username in allowedUsers;

// Return
!emailOk
  ? {
      ok: false,
      message: "Your email address is invalid",
      env: {},
    }
  : !emailDomainOk
  ? {
      ok: false,
      message:
        "Your email domain is not allowed (Expected one of: " +
        join(allowedDomains, ", ") +
        ", got: " +
        parsedEmail.domain +
        ")",
      env: {},
    }
  : !emailLocalOk
  ? {
      ok: false,
      message:
        "Your username does not match your email address (Expected: " +
        parsedEmail.local +
        ", got: " +
        username +
        ")",
      env: {},
    }
  : !usernameOk
  ? {
      ok: false,
      message: "You are not authorized to use PAM OAuth",
      env: {},
    }
  : {
      ok: true,
      message: "",
      env: {
        "COMMENT": email
      },
    }
```

_Note: this expression will only allow users with an email address from the `mail.example.com` subdomain to authenticate with PAM OAuth. Furthermore, users must connect using only the local part of their email address when using SSH (e.g.: `ssh username@mail.example.com`). If you allow multiple domains (instead of a single domain, as with the above), be careful to ensure that the `username` is unique across all domains (e.g.: suffix the username with some form of the domain name)._

### Development Setup

1. Install the tools:

- [Go](https://go.dev/dl/)
- [nFPM](https://nfpm.goreleaser.com/install/)
- [Taskfile](https://taskfile.dev/installation/#build-from-source)
- [GoSec](https://github.com/securego/gosec#local-installation)
- [gRPC](https://grpc.io/docs/languages/go/quickstart/)

2. Clone the repository:

```bash
git clone --recursive https://github.com/wakeful-cloud/pam-oauth.git
```

3. Install dependencies:

```bash
go mod download
```

### Audit

You can run all security audits with:

```bash
task audit
```

### Build

You can build everything with:

```bash
task build
```

### Package

You can package everything with:

```bash
task package
```

### Testing

1. Build everything using the [instructions above](#build)
2. Initialize the server

```bash
./dist/bin/pam-oauth-server --config ./dev/server.toml initialize --server-common-name localhost  --server-ip-san 127.0.0.1 --server-ip-san ::1 --server-ip-san 172.17.0.1
```

3. Update the [server configuration](./dev/server.toml) (e.g.: OAuth provider's details, listening address)

4. Add the client:

```bash
./dist/bin/pam-oauth-server --config ./dev/server.toml client add --client-common-name test --client-cert ./dev/internal-client.crt --client-key ./dev/internal-client.key
```

5. Initialize the client:

```bash
./dist/bin/pam-oauth-client --config ./dev/client.toml initialize
```

6. Update the [client configuration](./dev/client.toml) (e.g.: server's address)

7. Start the server:

```bash
go run ./cmd/server --config ./dev/server.toml serve
```

8. Start the persistent container:

```bash
docker run -it -d -v $(pwd):/go/src/github.com/wakeful-cloud/pam-oauth --name pam-oauth ubuntu:latest
```

9. Attach to the container:

```bash
docker exec -it pam-oauth /bin/bash
```

10. Setup the container:

```bash
# Install dependencies
apt update
apt install -y libpam0g libpam0g-dev nano openssh-server openssl

# Setup SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.old
sed -i -E -e 's/#?KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' -e 's/#?UsePAM no/UsePAM yes/' -e 's/#?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
ssh-keygen -a 100 -t ed25519 -f /root/.ssh/id_ed25519 -N ""
service ssh start && service ssh stop # Fix directory creation bug

# Setup PAM
cp /etc/pam.d/sshd /etc/pam.d/sshd.old
sed -i -E -e '1iauth sufficient /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/pam_oauth.so /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/pam-oauth-client --config /go/src/github.com/wakeful-cloud/pam-oauth/dev/client.toml run' /etc/pam.d/sshd

# Setup NSS
cp /etc/nsswitch.conf /etc/nsswitch.conf.old
sed -i -E -e 's/passwd: (.*)/passwd: \1 oauth/' -e 's/group: (.*)/group: \1 oauth/' /etc/nsswitch.conf

# Link the shared libraries
ln -s /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/libnss_oauth.so /lib/x86_64-linux-gnu/libnss_oauth.so
ln -s /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/libnss_oauth.so /lib/x86_64-linux-gnu/libnss_oauth.so.2

# Configure the login shell permissions
chown root:root /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/pam-oauth-login
chmod 6755 /go/src/github.com/wakeful-cloud/pam-oauth/dist/bin/pam-oauth-login
```

11. Start the SSH server:

```bash
/usr/sbin/sshd -D -d
```

12. In a new terminal, attatch to the container again and attempt to authenticate over SSH:

```bash
ssh username@localhost
```

### Structure

- `dist/`: build artifacts
  - `bin/`: compiled binaries
    - `pam-oauth-client`: client binary
    - `pam-oauth-login`: login shell binary
    - `pam-oauth-server`: server binary
  - `lib/`: shared libraries
    - `pam_oauth.so`: PAM module shared library
    - `libnss_oauth.so`: NSS module shared library
  - `man/`: man pages
  - `pkg/`: package archives
- `cmd/`: command line interfaces
  - `client/`: client command
  - `login/`: login shell command
  - `server/`: server command
- `internal/*`: internal packages
- `lib/*`: C shared libraries
  - `nss.c`: NSS stub resolver
  - `pam.c`: PAM module wrapper

### PAM Wrapper Protocol

The PAM module wrapper and client executable communicate using [NDJSON](https://github.com/ndjson/ndjson-spec) over standard output.

#### Standard Output Messages

##### `prompt`

- `type: string`: `"prompt"`
- `style: int`: the prompt style (1: echo off, 2: echo on, 3: error, 4: text info)
- `message: string`: the message to prompt the user

##### `putenv`

- `type: string`: `"putenv"`
- `name: string`: the name of the environment variable
- `value: string`: the value of the environment variable