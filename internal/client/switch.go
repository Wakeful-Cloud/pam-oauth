package client

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/samber/lo"
)

// safeEnvKeys is a list of environment keys that are safe to pass to the user's login shell
// See https://www.oreilly.com/library/view/ssh-the-secure/0596008953/apes12.html
var safeEnvKeys = []string{
	"DISPLAY",
	"LANG",
	"TERM",
	"XAUTHORITY",
	"LC_",

	"SSH2_AUTH_SOCK",
	"SSH2_CLIENT",
	"SSH2_TTY",
	"SSH_ASKPASS",
	"SSH_AUTH_SOCK",
	"SSH_CLIENT",
	"SSH_CONNECTION",
	"SSH_ORIGINAL_COMMAND",
	"SSH_ORIGINAL_COMMAND2",
	"SSH_SOCKS_SERVER",
	"SSH_TTY",
}

// SwitchUser switches the current process to the specified user
func SwitchUser(user *Passwd) error {
	// Switch to the group
	err := syscall.Setgid(user.Gid)

	if err != nil {
		return err
	}

	// Switch to the user
	err = syscall.Setuid(user.Uid)

	if err != nil {
		return err
	}

	// Switch to the user's home directory
	err = os.Chdir(user.Dir)

	if err != nil {
		return err
	}

	// Get the current environment
	env := lo.Filter(os.Environ(), func(item string, _ int) bool {
		// Parse the item
		parts := strings.SplitN(item, "=", 2)

		for _, key := range safeEnvKeys {
			if strings.HasPrefix(parts[0], key) {
				return true
			}
		}

		return false
	})

	// Switch to the user's login shell
	// #nosec G204
	err = syscall.Exec(user.Shell, []string{fmt.Sprintf("-%s", user.Shell)}, env)

	if err != nil {
		return err
	}

	return fmt.Errorf("failed to switch to the user's login shell")
}
