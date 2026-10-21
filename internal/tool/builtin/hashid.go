package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"reasonix/internal/tool"
)

func init() { tool.RegisterBuiltin(hashIdentify{}) }

type hashIdentify struct{}

func (hashIdentify) Name() string { return "hash_identify" }

func (hashIdentify) Description() string {
	return "Identify the likely hash type of a given hash string. Recognizes MD5, SHA-1, SHA-256, SHA-512, NTLM, LM, bcrypt, SHA-512crypt, MySQL, CRC32, Base64, and many more hash formats based on length and character patterns."
}

func (hashIdentify) Schema() json.RawMessage {
	return json.RawMessage(`{
"type":"object",
"properties":{
	"hash":{"type":"string","description":"Hash string to identify"},
	"multiple":{"type":"boolean","description":"Return multiple possible matches (default true)"}
},
"required":["hash"]
}`)
}

func (hashIdentify) ReadOnly() bool { return true }

type hashPattern struct {
	Name    string
	Regex   *regexp.Regexp
	Lengths []int
	Example string
}

var hashPatterns []hashPattern

func init() {
	patterns := []struct {
		name    string
		re      string
		lengths []int
		example string
	}{
		{"MD5", `^[a-f0-9]{32}$`, []int{32}, "5d41402abc4b2a76b9719d911017c592"},
		{"MD4", `^[a-f0-9]{32}$`, []int{32}, ""},
		{"NTLM", `^[A-F0-9]{32}$`, []int{32}, "E52CAC67419A9A224A3B108F3FA6CB6D"},
		{"LM", `^[A-F0-9]{32}$`, []int{32}, "E52CAC67419A9A224A3B108F3FA6CB6D"},
		{"SHA-1", `^[a-f0-9]{40}$`, []int{40}, "2ef7bde608ce5404e97d5f042f95f89f1c232871"},
		{"SHA-256", `^[a-f0-9]{64}$`, []int{64}, "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
		{"SHA-512", `^[a-f0-9]{128}$`, []int{128}, ""},
		{"SHA-384", `^[a-f0-9]{96}$`, []int{96}, ""},
		{"SHA-224", `^[a-f0-9]{56}$`, []int{56}, ""},
		{"MySQL3", `^[a-f0-9]{16}$`, []int{16}, ""},
		{"MySQL5", `^\*[A-F0-9]{40}$`, []int{41}, "*E8C4E4E6B1A6C4E4E6B1A6C4E4E6B1A6C4E4E6A6"},
		{"SHA-512crypt ($6$)", `^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$`, nil, "$6$salt$hash"},
		{"SHA-256crypt ($5$)", `^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$`, nil, "$5$salt$hash"},
		{"bcrypt ($2a$)", `^\$2[aby]\$\d+\$[a-zA-Z0-9./]+$`, nil, "$2a$10$saltvaluewithhash"},
		{"bcrypt ($2b$)", `^\$2[aby]\$\d+\$[a-zA-Z0-9./]+$`, nil, "$2b$10$saltvaluewithhash"},
		{"bcrypt ($2y$)", `^\$2[aby]\$\d+\$[a-zA-Z0-9./]+$`, nil, "$2y$10$saltvaluewithhash"},
		{"MD5crypt ($1$)", `^\$1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$`, nil, "$1$salt$hash"},
		{"Apache MD5 ($apr1$)", `^\$apr1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$`, nil, "$apr1$salt$hash"},
		{"CRC32", `^[a-f0-9]{8}$`, []int{8}, "d41d8cd9"},
		{"CRC16", `^[a-f0-9]{4}$`, []int{4}, "0000"},
		{"Base64", `^[a-zA-Z0-9+/]+={0,2}$`, nil, "dGhpcyBpcyBhIHRlc3Q="},
		{"Base32", `^[A-Z2-7]+=*$`, nil, "ORSXG5A="},
		{"Hex (generic)", `^[a-fA-F0-9]+$`, nil, ""},
		{"SSH RSA Public Key", `^ssh-rsa [a-zA-Z0-9+/]+=*`, nil, "ssh-rsa AAAAB3Nza..."},
		{"UUID", `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`, []int{36}, ""},
		{"JWT Token", `^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`, nil, "eyJhbG...eyJzdW...SflKx..."},
		{"Bitcoin Address", `^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`, nil, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
	}

	for _, p := range patterns {
		hashPatterns = append(hashPatterns, hashPattern{
			Name:    p.name,
			Regex:   regexp.MustCompile(p.re),
			Lengths: p.lengths,
			Example: p.example,
		})
	}
}

func (hashIdentify) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	p := struct {
		Hash     string `json:"hash"`
		Multiple bool   `json:"multiple"`
	}{Multiple: true}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &p); err != nil {
			return "", fmt.Errorf("invalid args: %w", err)
		}
	}
	if p.Hash == "" {
		return "", fmt.Errorf("hash is required")
	}

	hash := strings.TrimSpace(p.Hash)
	var matches []string

	for _, pat := range hashPatterns {
		if pat.Regex.MatchString(hash) {
			// Some patterns need length check
			if len(pat.Lengths) > 0 {
				matched := false
				for _, l := range pat.Lengths {
					if len(hash) == l {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
			// Avoid generic matches like "Hex (generic)" if more specific matches exist
			matches = append(matches, pat.Name)
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Hash analysis for: %s (length: %d)\n\n", hash, len(hash)))

	if len(matches) == 0 {
		b.WriteString("No matching hash format found. The hash may be:\n")
		b.WriteString("- An unknown or proprietary format\n")
		b.WriteString("- Truncated or malformed\n")
		b.WriteString("- An encrypted value (not a hash)\n\n")
		b.WriteString("Try using bash to invoke hashid or hash-identifier tools for more formats.\n")
	} else if len(matches) == 1 || !p.Multiple {
		b.WriteString(fmt.Sprintf("Identified: %s\n\n", matches[0]))
		b.WriteString("Hashcat mode reference:\n")
		b.WriteString(hashcatModes(matches[0]))
	} else {
		b.WriteString("Possible matches (ordered by likelihood):\n")
		for _, m := range matches {
			b.WriteString(fmt.Sprintf("• %s\n", m))
		}
		b.WriteString("\nTo narrow down, consider context:\n")
		b.WriteString("- OS: Windows (NTLM), Linux (SHA-512crypt), Web (bcrypt/MD5)\n")
		b.WriteString("- Source: /etc/shadow, database dump, cookie, API token\n")
	}

	return b.String(), nil
}

func hashcatModes(name string) string {
	modes := map[string]string{
		"MD5":              "  0 = MD5\n",
		"MD4":              "900 = MD4\n",
		"NTLM":             "1000 = NTLM\n",
		"LM":               "3000 = LM\n",
		"SHA-1":            " 100 = SHA1\n",
		"SHA-256":          "1400 = SHA2-256\n",
		"SHA-512":          "1700 = SHA2-512\n",
		"bcrypt ($2a$)":    "3200 = bcrypt\n",
		"SHA-512crypt ($6$)": "1800 = sha512crypt $6$\n",
		"SHA-256crypt ($5$)": "7400 = sha256crypt $5$\n",
		"MD5crypt ($1$)":   " 500 = md5crypt $1$\n",
		"Apache MD5 ($apr1$)": "1600 = Apache $apr1$\n",
		"MySQL5":           " 300 = MySQL4.1/MySQL5\n",
		"MySQL3":           " 200 = MySQL3.x\n",
	}
	if m, ok := modes[name]; ok {
		return m
	}
	return "Mode not directly mapped; check hashcat --help\n"
}
