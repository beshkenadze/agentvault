package loginitem

import (
	"strings"
	"text/template"
)

const labelAvd = "app.bshk.agentvault.avd"

type launchAgentVars struct {
	Label   string
	AvdPath string
	LogDir  string
}

// launchAgentPlistTmpl is the fallback (build-from-source) LaunchAgent. Unlike the
// bundled SMAppService plist it uses an ABSOLUTE ProgramArguments path (avd knows it
// at render time via os.Executable) and Interactive ProcessType so LocalAuthentication
// can present Touch ID in the GUI session. No secret values ever appear here.
var launchAgentPlistTmpl = template.Must(template.New("la").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.AvdPath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/avd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/avd.err.log</string>
</dict>
</plist>
`))

func renderLaunchAgentPlist(v launchAgentVars) (string, error) {
	var b strings.Builder
	if err := launchAgentPlistTmpl.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}
