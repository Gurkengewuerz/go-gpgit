package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"git.gurkengewuerz.de/Gurkengewuerz/go-gpgmime"
	"github.com/emersion/go-message"
	"gopkg.in/ini.v1"
	"gopkg.in/ldap.v3"
)

var config *ini.File

func getArmoredKeyRing(recipient *string) (string, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	l, err := ldap.DialTLS(
		"tcp",
		fmt.Sprintf("%s:%s", config.Section("ldap").Key("host").String(), config.Section("ldap").Key("port").String()),
		tlsConfig)

	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	keyAttribute := config.Section("ldap").Key("key_attribute").String()
	searchRequest := ldap.NewSearchRequest(
		config.Section("ldap").Key("search_base").String(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(config.Section("ldap").Key("query_filter").String(), *recipient),
		[]string{"dn", "uid", keyAttribute}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	if len(sr.Entries) > 1 || len(sr.Entries) == 0 {
		return "", fmt.Errorf("to many or none entries %d", len(sr.Entries))
	}

	entry := sr.Entries[0]
	return entry.GetAttributeValue(keyAttribute), nil
}

func isPGPMessage(msg string) (bool, error) {
	matched, err := regexp.MatchString(`-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----`, msg)
	return matched, err
}

func isEncrypted(mail *message.Entity) bool {
	t, _, _ := mail.Header.ContentType()
	if strings.ToLower(t) == "multipart/encrypted" {
		return true
	}

	if mail.MultipartReader() == nil {
		if b, err := ioutil.ReadAll(mail.Body); err == nil {
			enc, _ := isPGPMessage(string(b))
			if enc {
				return true
			}
		}
	}
	return false
}

func encryptEML(eml string, armoredKeyRing *string) {
	var b bytes.Buffer
	var r, r2 io.Reader

	r = strings.NewReader(eml)

	m, err := message.Read(r)
	if err != nil {
		log.Fatal(err)
	}

	origMimeVersion := m.Header.Get("MIME-Version")
	origContentType := m.Header.Get("Content-Type")

	if isEncrypted(m) {
		log.Print(eml)
		os.Exit(0)
	}

	r2 = strings.NewReader(*armoredKeyRing)
	entityList, err := openpgp.ReadArmoredKeyRing(r2)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new PGP/MIME writer
	var ciphertext struct{ *message.Writer }
	cleartext := pgpmime.Encrypt(&ciphertext, nil, entityList, nil, nil)

	// Add the PGP/MIME Content-Type header field to the mail header
	m.Header.Set("Content-Type", cleartext.ContentType())
	m.Header.Set(
		"X-Encrypted-By",
		fmt.Sprintf("%s-v%s", config.Section("").Key("service_name").String(), config.Section("").Key("version").String()))

	// Create a new mail writer with our mail header
	mw, err := message.CreateWriter(&b, m.Header)
	if err != nil {
		log.Fatal(err)
	}
	// Set the PGP/MIME writer output to the mail body
	ciphertext.Writer = mw

	_, _ = io.WriteString(ciphertext.Writer, "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\n")

	// Write the cleartext body
	if b, err := ioutil.ReadAll(m.Body); err == nil {
		if origMimeVersion != "" {
			origContentType = "Content-Type: " + origContentType
			origContentType = strings.Replace(origContentType, "\r\n", "", 1)
			origContentType = strings.Replace(origContentType, "\n", "", 1)

			pat := regexp.MustCompile(`Type:\s*(.*?);\sboundary="(.*?)"`)
			matches := pat.FindAllStringSubmatch(origContentType, -1)

			if len(matches) == 0 {
				os.Exit(1)
			}

			_, _ = io.WriteString(cleartext, fmt.Sprintf("Content-Type: %s;\n boundary=\"%s\"\n\n", matches[0][1], matches[0][2]))
		}

		_, err = io.WriteString(cleartext, string(b))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Close all writers
	if err := cleartext.Close(); err != nil {
		log.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		log.Fatal(err)
	}

	fmt.Print(b.String())
}

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}

	if !strings.HasPrefix(dir, os.TempDir()) {
		err = os.Chdir(dir)
		if err != nil {
			log.Fatal(err)
		}
	}

	cfg, err := ini.Load("config.ini")
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}

	config = cfg

	argsWithoutProg := os.Args[1:]

	if len(argsWithoutProg) != 1 {
		log.Fatal("No recipient as argument")
	}
	recipient := argsWithoutProg[0]

	fi, err := os.Stdin.Stat()
	if err != nil {
		log.Fatal(err)
	}

	if fi.Mode()&os.ModeNamedPipe == 0 {
		if fi.Size() == 0 {
			log.Fatal("stdin is empty")
		}
	}

	data, err := ioutil.ReadAll(os.Stdin)
	rawEml := string(data)

	armoredKeyRing, err := getArmoredKeyRing(&recipient)
	if err != nil {
		log.Fatal(err)
	}

	encryptEML(rawEml, &armoredKeyRing)
	os.Exit(0)
}
