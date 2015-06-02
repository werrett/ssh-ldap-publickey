package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/mavricknz/ldap"
)

var config = make(map[string]string)
var configFile = "/etc/openldap/ldap.conf"
var configRegexp = regexp.MustCompile(`^(\w+)\s+(.+)$`)
var sshAttributeName = "sshPublicKey"
var flagVerbose bool

func init() {
	flag.BoolVar(&flagVerbose, "verbose", false,
		"Print errors rather than failing silently")
}

func main() {

	flag.Parse()

	args := flag.Args()
  if len(args) != 1 {
		fmt.Println("Must provide user account name.")
		fmt.Println()
		fmt.Println("Usage: ssh-ldap-publickey [-verbose] user")
		os.Exit(1)
  }

	uid := strings.TrimSpace(args[0])
	// TODO: Whitelist uid. No LDAP query characters.

	loadConfig()
	// TODO: Sanity check config

	var filter string
	pamFilter := config["pam_filter"]

	if pamFilter == "" {
		filter = fmt.Sprintf("(uid=%s)", uid)
	} else {
		filter = fmt.Sprintf("(&(%s)(uid=%s))", pamFilter, uid)
	}

	attributes := []string{sshAttributeName}

	port, err := strconv.ParseUint(config["port"], 10, 16)
	check(err)

	tlsConfig := tls.Config{InsecureSkipVerify: true}

	ldapConn := ldap.NewLDAPSSLConnection(config["host"],
		uint16(port), &tlsConfig)

	err = ldapConn.Connect()
	check(err)

	err = ldapConn.Bind(config["binddn"], config["bindpw"])
	check(err)

	var searchBase string
	if config["nss_base_passwd"] != "" {
		searchBase = config["nss_base_passwd"]
	} else {
		searchBase = config["base"]
	}

	userSearch := ldap.NewSimpleSearchRequest(
		searchBase, ldap.ScopeSingleLevel, filter, attributes,
	)

	result, err := ldapConn.Search(userSearch)
	check(err)

	if len(result.Entries) > 1 {
		newError("Search returned more than one user account")
	} else if len(result.Entries) < 1 {
		newError("No user accounts match search")
	}

	var sshAttributeFound = false
	for _, v := range result.Entries[0].Attributes {
		if v.Name == sshAttributeName {
			fmt.Println(v.Values[0])
			sshAttributeFound = true
		}
	}
	if !sshAttributeFound {
		newError("SSH Public Key not found")
	}
}

// Load configuration from file. Set the config map.
func loadConfig() {
	file, err := os.Open(configFile)
	check(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		v := configRegexp.FindStringSubmatch(line)
		if len(v) != 0 {
			if v[1] != "" && v[2] != "" {
				config[strings.ToLower(v[1])] = v[2]
			}
		}
	}

	err = scanner.Err()
	check(err)

	u, err := url.Parse(config["uri"])
	check(err)

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil { // Then no port specified
		host = u.Host
		if u.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}

	config["scheme"] = u.Scheme
	config["host"] = host
	config["port"] = port
}
