package client

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// EvaluateTextTemplate evaluates the specified text (i.e.: **NON-HTML**) template with the specified data
func EvaluateTextTemplate(rawTemplate string, data any) (string, error) {
	// Parse the template
	parsed, err := template.New("template").Parse(rawTemplate)

	if err != nil {
		return "", err
	}

	// Execute the template
	buffer := bytes.Buffer{}
	err = parsed.Execute(&buffer, data)

	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}

// shellParser is the shell parser
var shellParser = syntax.NewParser()

// EvaluateShellScript evaluates the specified shell script with the specified timeout
func EvaluateShellScript(raw string, timeout time.Duration, env map[string]string) (string, string, error) {
	// Generate the environment variables
	environment := os.Environ()

	for key, value := range env {
		environment = append(environment, fmt.Sprintf("%s=%s", key, value))
	}

	// Parse the shell script
	file, err := shellParser.Parse(strings.NewReader(raw), "")

	if err != nil {
		return "", "", err
	}

	// Initialize the runner
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	runner, err := interp.New(
		interp.Env(expand.ListEnviron(environment...)),
		interp.StdIO(nil, &stdout, &stderr),
	)

	if err != nil {
		return "", "", err
	}

	// Run the shell script
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = runner.Run(ctx, file)

	return stdout.String(), stderr.String(), err
}
