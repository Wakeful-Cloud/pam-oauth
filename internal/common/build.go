package common

import (
	"fmt"
	"runtime"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/samber/lo"
)

// rawVersion is the raw version string of the application (set at build time)
var rawVersion = "0.0.0"

// rawCommit is the raw commit the application was built from (set at build time)
var rawCommit = "unknown"

// rawBranch is the raw branch the application was built from (set at build time)
var rawBranch = "unknown"

// rawTimestamp is the raw time the application was built (set at build time)
var rawTimestamp = "1970-01-01T00:00:00Z"

// Version is the version of the application
var Version = lo.Must(version.NewSemver(rawVersion))

// VersionConstraint is the version constraint of the application
var VersionConstraint = lo.Must(version.NewConstraint(fmt.Sprintf("~> %d.%d", Version.Segments()[0], Version.Segments()[1])))

// Commit is the commit the application was built from
var Commit = rawCommit

// Branch is the branch the application was built from
var Branch = rawBranch

// Timestamp is the time the application was built
var Timestamp = lo.Must(time.Parse(time.RFC3339, rawTimestamp))

// About is the about string
var About = fmt.Sprintf("%s (Build %s@%s at %s with %s)", Version, Commit, Branch, Timestamp.Format(time.RFC3339), runtime.Version())
