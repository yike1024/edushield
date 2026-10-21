package builtin

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(forensicExtract{}) }

type forensicExtract struct{}

func (forensicExtract) Name() string { return "forensic_extract" }

func (forensicExtract) Description() string {
	return "Extract forensic artifacts from a file: compute file hashes (MD5, SHA-1, SHA-256), extract embedded strings (ASCII and UTF-8), detect file type via magic bytes, extract IP addresses, email addresses, URLs, and file paths from binary content. Useful for malware triage, log analysis, and artifact examination."
}

func (forensicExtract) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"path":{"type":"string","description":"Path to the file to analyze"},
	"extractions":{"type":"string","description":"Comma-separated list: 'hashes', 'strings', 'magic', 'iocs', 'all'. Default: 'all'"},
	"strings_min_length":{"type":"integer","description":"Minimum length for string extraction (default 4)"},
	"strings_count":{"type":"integer","description":"Max number of strings to return (default 200)"}
},
"required":["path"]
}`)
}

func (forensicExtract) ReadOnly() bool { return true }

var (
	ipv4Regex       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	emailRegex      = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	urlRegex        = regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	filepathWinRegex = regexp.MustCompile(`[A-Za-z]:\\[^\s<>"{}|\\^` + "`" + `\[\]]+`)
	filepathUnixRegex = regexp.MustCompile(`/(?:home|root|etc|tmp|var|opt|usr)/[^\s<>"{}|\\^` + "`" + `\[\]]+`)
)

var magicSignatures = map[string][]byte{
	"PK (ZIP/DOCX/JAR)":   {0x50, 0x4B, 0x03, 0x04},
	"MZ (PE/EXE)":         {0x4D, 0x5A},
	"\x7FELF (ELF binary)": {0x7F, 0x45, 0x4C, 0x46},
	"%PDF":                {0x25, 0x50, 0x44, 0x46},
	"\x89PNG":             {0x89, 0x50, 0x4E, 0x47},
	"GIF89a":              {0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
	"GIF87a":              {0x47, 0x49, 0x46, 0x38, 0x37, 0x61},
	"\xFF\xD8\xFF (JPEG)": {0xFF, 0xD8, 0xFF},
	"RIFF (WAV/AVI)":      {0x52, 0x49, 0x46, 0x46},
	"ID3 (MP3)":           {0x49, 0x44, 0x33},
	"OggS (OGG)":          {0x4F, 0x67, 0x67, 0x53},
	"CA FE BA BE (Java class)": {0xCA, 0xFE, 0xBA, 0xBE},
	"Rar!":                {0x52, 0x61, 0x72, 0x21},
	"7z\xBC\xAF":          {0x37, 0x7A, 0xBC, 0xAF},
	"SQLite3":             {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65},
	"#!/bin (script)":     {0x23, 0x21, 0x2F, 0x62, 0x69, 0x6E},
	"<?xml":              {0x3C, 0x3F, 0x78, 0x6D, 0x6C},
	"<!DOCTYPE":          {0x3C, 0x21, 0x44, 0x4F, 0x43},
}

func (forensicExtract) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Path             string `json:"path"`
		Extractions      string `json:"extractions"`
		StringsMinLength int    `json:"strings_min_length"`
		StringsCount     int    `json:"strings_count"`
	}{Extractions: "all", StringsMinLength: 4, StringsCount: 200}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	if p.StringsMinLength < 2 {
		p.StringsMinLength = 2
	}
	if p.StringsCount < 1 {
		p.StringsCount = 1
	}
	if p.StringsCount > 1000 {
		p.StringsCount = 1000
	}

	fi, err := os.Stat(p.Path)
	if err != nil {
		return "", fmt.Errorf("cannot access file: %w", err)
	}

	f, err := os.Open(p.Path)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	checks := map[string]bool{}
	for _, c := range strings.Split(p.Extractions, ",") {
		checks[strings.TrimSpace(c)] = true
	}
	runAll := checks["all"]

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Forensic Analysis: %s\n", p.Path))
	b.WriteString(fmt.Sprintf("Size: %d bytes | Mode: %s | ModTime: %s\n\n",
		fi.Size(), fi.Mode().String(), fi.ModTime().Format("2006-01-02 15:04:05")))

	// Read file content (up to 16MB for large files)
	maxRead := int64(16 << 20)
	if fi.Size() > maxRead {
		b.WriteString(fmt.Sprintf("⚠ File is %d bytes; analyzing first %d bytes\n\n", fi.Size(), maxRead))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil {
		return "", fmt.Errorf("cannot read file: %w", err)
	}

	// 1. Hashes
	if runAll || checks["hashes"] {
		b.WriteString("--- File Hashes ---\n")
		md5h := md5.Sum(data)
		sha1h := sha1.Sum(data)
		sha256h := sha256.Sum256(data)
		b.WriteString(fmt.Sprintf("MD5:    %s\n", hex.EncodeToString(md5h[:])))
		b.WriteString(fmt.Sprintf("SHA-1:  %s\n", hex.EncodeToString(sha1h[:])))
		b.WriteString(fmt.Sprintf("SHA-256:%s\n", hex.EncodeToString(sha256h[:])))
		b.WriteString(fmt.Sprintf("\nVirusTotal lookup: https://www.virustotal.com/gui/file/%s\n", hex.EncodeToString(sha256h[:])))
		b.WriteString("\n")
	}

	// 2. Magic bytes
	if runAll || checks["magic"] {
		b.WriteString("--- File Type (Magic Bytes) ---\n")
		matched := false
		for label, sig := range magicSignatures {
			if len(data) >= len(sig) {
				match := true
				for i, b2 := range sig {
					if data[i] != b2 {
						match = false
						break
					}
				}
				if match {
					b.WriteString(fmt.Sprintf("Detected: %s\n", label))
					matched = true
					break
				}
			}
		}
		if !matched {
			// Check if it's plain text
			isText := true
			for _, b2 := range data[:min(len(data), 1024)] {
				if b2 == 0 {
					isText = false
					break
				}
				if b2 < 0x09 || (b2 > 0x0D && b2 < 0x20) && b2 != 0x1B {
					isText = false
					break
				}
			}
			if isText && utf8.Valid(data[:min(len(data), 1024)]) {
				b.WriteString("Appears to be: plain text (UTF-8)\n")
			} else {
				b.WriteString("Unknown binary format (no known magic bytes matched)\n")
			}
		}
		b.WriteString("\n")
	}

	// 3. Strings extraction
	if runAll || checks["strings"] {
		b.WriteString(fmt.Sprintf("--- Extracted Strings (min=%d, max=%d) ---\n", p.StringsMinLength, p.StringsCount))
		var current []byte
		count := 0
		for _, b2 := range data {
			if b2 >= 0x20 && b2 < 0x7F {
				current = append(current, b2)
			} else {
				if len(current) >= p.StringsMinLength && count < p.StringsCount {
					b.WriteString(string(current) + "\n")
					count++
				}
				current = current[:0]
			}
		}
		if len(current) >= p.StringsMinLength && count < p.StringsCount {
			b.WriteString(string(current) + "\n")
			count++
		}
		if count == 0 {
			b.WriteString("No strings found.\n")
		}
		b.WriteString("\n")
	}

	// 4. IOC extraction
	if runAll || checks["iocs"] {
		b.WriteString("--- IOC Extraction ---\n")
		text := string(data)

		ipSeen := map[string]bool{}
		emailSeen := map[string]bool{}
		urlSeen := map[string]bool{}

		// IP addresses (exclude private/reserved)
		for _, ip := range ipv4Regex.FindAllString(text, -1) {
			if !ipSeen[ip] && !isPrivateOrReservedIP(ip) {
				ipSeen[ip] = true
			}
		}
		if len(ipSeen) > 0 {
			b.WriteString("IP Addresses:\n")
			for ip := range ipSeen {
				b.WriteString(fmt.Sprintf("  %s\n", ip))
			}
		}

		// Email addresses
		for _, email := range emailRegex.FindAllString(text, -1) {
			if !emailSeen[email] {
				emailSeen[email] = true
			}
		}
		if len(emailSeen) > 0 {
			b.WriteString("Email Addresses:\n")
			for email := range emailSeen {
				b.WriteString(fmt.Sprintf("  %s\n", email))
			}
		}

		// URLs
		for _, u := range urlRegex.FindAllString(text, -1) {
			if !urlSeen[u] {
				urlSeen[u] = true
			}
		}
		if len(urlSeen) > 0 {
			b.WriteString("URLs:\n")
			for u := range urlSeen {
				b.WriteString(fmt.Sprintf("  %s\n", u))
			}
		}

		// File paths
		paths := append(filepathWinRegex.FindAllString(text, -1), filepathUnixRegex.FindAllString(text, -1)...)
		pathSeen := map[string]bool{}
		deduped := []string{}
		for _, pth := range paths {
			if !pathSeen[pth] {
				pathSeen[pth] = true
				deduped = append(deduped, pth)
			}
		}
		if len(deduped) > 0 {
			b.WriteString("File Paths:\n")
			for _, pth := range deduped {
				b.WriteString(fmt.Sprintf("  %s\n", pth))
			}
		}

		if len(ipSeen) == 0 && len(emailSeen) == 0 && len(urlSeen) == 0 && len(deduped) == 0 {
			b.WriteString("No IOCs (IPs, emails, URLs, paths) found.\n")
		}
	}

	return strings.TrimSpace(b.String()), nil
}

func isPrivateOrReservedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	return isPrivateIP(parsed)
}
