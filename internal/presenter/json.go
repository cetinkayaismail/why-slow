// Package presenter — json.go renders DiagnosticReport as machine-readable
// JSON to stdout. Includes privilege_level metadata.
// Pretty-prints by default, compact with pretty=false.
package presenter

import (
	"encoding/json"
	"fmt"
	"io"
	"why-slow/internal/analyzer"
)

// RenderJSON writes the diagnostic report as structured JSON to w.
func RenderJSON(w io.Writer, report *analyzer.DiagnosticReport, pretty bool) error {
	if report == nil {
		return fmt.Errorf("presenter: report is nil")
	}

	var data []byte
	var err error

	if pretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Errorf("presenter: marshal json: %w", err)
	}

	_, err = w.Write(append(data, '\n'))
	return err
}
