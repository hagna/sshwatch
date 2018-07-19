package main

import (
	"bufio"
	"fmt"
	"github.com/gravwell/ingest"
	"github.com/gravwell/ingest/entry"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var password = flag.StringP("password", "p", "words!@#", "Password")
var TAGNAME = flag.StringP("tagname", "t", "word", "gravwell tag name")
var SECRET = flag.StringP("secret", "s", "asdfasdf", "gravwell secret")
var keyfilename = flag.String("keyfile", os.Getenv("HOME")+"/.ssh/id_rsa", "key file")
var prog = os.Args[0]
var docu = "[user@]hostname[:port] \"command\""
var WAIT = flag.DurationP("interval", "n", time.Second*2, "Number of seconds to wait between runs")

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s: %s [options] %s\n", prog, prog, docu)
	flag.PrintDefaults()
}

func initIngest(tagname, isecret string) (*ingest.IngestConnection, error) {

	igst, err := ingest.InitializeConnection("tcp://127.0.0.1:4023", isecret, []string{tagname}, "", "", false)
	if err != nil {
		return nil, err
	}
	return igst, err
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
		log.Fatal(err)
	}
	defer client.Close()

	igst, err := initIngest(*TAGNAME, *SECRET)
	if err != nil {
		log.Fatal(err)
	}

	defer igst.Close()
	r, w := io.Pipe()
	tagid, ok := igst.GetTag(*TAGNAME)
	if !ok {
		log.Fatal("couldn't look up tag")
	}
	go func() {
		s := bufio.NewScanner(r)
		for s.Scan() {
			// Now we'll create an Entry
			ent := entry.Entry{
				TS:   entry.Now(),
				SRC:  net.ParseIP("127.0.0.1"),
				Tag:  tagid,
				Data: []byte(s.Text()),
			}

			// And finally write the Entry
			err := igst.WriteEntrySync(&ent)
			if err != nil {
				log.Println(err)
			} else {
				log.Println("SENT " + s.Text())
			}
		}
	}()
	for {
		sess, err := client.NewSession()
		if err != nil {
			log.Fatal(err)
		}
		sess.Stdout = w
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
