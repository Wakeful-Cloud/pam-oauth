package server

import (
	"embed"
	"html/template"
	"io"
)

// rawStaticFiles is the raw embedded static content filesystem
//
//go:embed web/static
var staticFiles embed.FS

// rawFlowEndPage is the raw OAuth flow end page
//
//go:embed web/templates/flow-end.html
var rawFlowEndPage string

// flowEndPage is the OAuth flow end page
var flowEndPage = template.Must(template.New("flowEndPage").Parse(rawFlowEndPage))

// flowEndPageEnv is the environment for the OAuth flow end page
type flowEndPageEnv struct {
	Code    string `json:"code"`    // The verification code
	Message string `json:"message"` // The message
}

// renderFlowPage renders the OAuth flow page
func renderFlowPage(writer io.Writer, env flowEndPageEnv) error {
	return flowEndPage.Execute(writer, env)
}
