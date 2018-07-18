package main

import (
	"fmt"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"time"
)

var password = flag.StringP("password", "p", "words!@#", "Password")
var keyfilename = flag.String("keyfile", os.Getenv("HOME")+"/.ssh/id_rsa", "key file")
var prog = os.Args[0]
var docu = "[user@]hostname[:port] \"command\""
var WAIT = flag.DurationP("interval", "n", time.Second*2, "Number of seconds to wait between runs")

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s: %s [options] %s\n", prog, prog, docu)
	flag.PrintDefaults()
}

func main() {

	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 2 {
		fmt.Println(prog + ": You must specify " + prog + " " + docu + "\nTry '" + prog + " --help' for more information.\n")
		return
	}
	var host string
	var user string
	var port string
	uh := flag.Arg(0)
	i := strings.Index(uh, "@")
	if i == -1 {
		host = uh
	} else {
		host = uh[i+1:]
		user = uh[:i]
	}
	i = strings.Index(uh, ":")
	if i == -1 {
		port = "22"
	} else {
		port = uh[i+1:]
	}
	pass := *password
	cmd := flag.Arg(1)

	// get host public key
	hostKeyfile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	hostKeyCB, err := knownhosts.New(hostKeyfile)
	if err != nil {
		log.Fatal("Error setting up knownhost callback: %s", err)
	}

	// ssh client config
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.RetryableAuthMethod(ssh.Password(pass), 10),
			PublicKeyFile(*keyfilename),
		},

		// verify host public key
		HostKeyCallback: hostKeyCB,
	}

	// connect
	client, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		log.Println("Error on ssh.Dial")
		log.Fatal(err)
	}
	defer client.Close()
	for {
		sess, err := client.NewSession()
		if err != nil {
			log.Println("error on NEwSession()")
			log.Fatal(err)
		}
		// setup standard out and error
		// uses writer interface
		sess.Stdout = os.Stdout
		sess.Stderr = os.Stderr

		err = sess.Run(cmd)
		if err != nil {
			log.Println(err)
			break
		}
		sess.Close()
		time.Sleep(*WAIT)
	}

}

func PublicKeyFile(file string) ssh.AuthMethod {
	log.Println("pubkeyfile is %s", file)
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}
