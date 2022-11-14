package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/vkuznet/x509proxy"
)

// version of the code
var version string

// helper function to return version string of the server
func info() string {
	goVersion := runtime.Version()
	tstamp := time.Now().Format("2006-02-01")
	return fmt.Sprintf("cert-checker git=%s go=%s date=%s", version, goVersion, tstamp)
}

// main function
func main() {
	var cert string
	flag.StringVar(&cert, "cert", "", "file certificate (PEM file name) or X509 proxy")
	var ckey string
	flag.StringVar(&ckey, "ckey", "", "file certficate private key (PEM file name)")
	var alert string
	flag.StringVar(&alert, "alert", "", "alert email or URL")
	var interval int
	flag.IntVar(&interval, "interval", 600, "interval before expiration (in seconds)")
	var version bool
	flag.BoolVar(&version, "version", false, "print version information about the server")
	var daemonInterval int
	flag.IntVar(&daemonInterval, "daemon", 0, "run as daemon with provided interval value")
	var token string
	flag.StringVar(&token, "token", "", "token string or file containing the token")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	token = getToken(token)
	if daemonInterval > 0 {
		for {
			check(cert, ckey, alert, interval, token)
			time.Sleep(time.Duration(daemonInterval) * time.Second)
		}
	} else {
		check(cert, ckey, alert, interval, token)
	}
}

// helper function to get token
func getToken(t string) string {
	if _, err := os.Stat(t); err == nil {
		b, e := ioutil.ReadFile(t)
		if e != nil {
			log.Fatalf("Unable to read data from file: %s, error: %s", t, e)
		}
		return strings.Replace(string(b), "\n", "", -1)
	}
	return t
}

// check given cert/key or X509 proxy for its expiration in time+interval range
func check(cert, ckey, alert string, interval int, token string) {
	certs, err := getCert(cert, ckey)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			if strings.Contains(alert, "@") {
				sendEmail(alert, err.Error())
			} else {
				sendNotification(alert, err.Error(), token)
			}
			return
		}
		log.Fatalf("Unable to read certificate cert=%s, ckey=%s, error=%v", cert, ckey, err)
	}
	tsCert := CertExpire(certs)
	ts := time.Now().Add(time.Duration(interval) * time.Second)
	if tsCert.Before(ts) {
		msg := fmt.Sprintf("certificate timestamp: %v will expire soon", tsCert)
		if strings.Contains(alert, "@") {
			sendEmail(alert, msg)
		} else {
			sendNotification(alert, msg, token)
		}
		log.Printf("WARNING: %s alert send to %s", msg, alert)
	} else {
		log.Printf("Certificate %s expires on %v, well after interval=%d (sec) or %v", cert, tsCert, interval, ts)
	}

}

// helper function to get certificates for provide cert/key PEM files
func getCert(cert, ckey string) ([]tls.Certificate, error) {
	var x509cert tls.Certificate
	var err error
	if cert != "" && ckey != "" {
		x509cert, err = tls.LoadX509KeyPair(cert, ckey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cert/key PEM pair: %v", err)
		}
	} else {
		x509cert, err = x509proxy.LoadX509Proxy(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X509 proxy: %v", err)
		}
	}
	certs := []tls.Certificate{x509cert}
	return certs, nil
}

// CertExpire gets minimum certificate expire from list of certificates
func CertExpire(certs []tls.Certificate) time.Time {
	var notAfter time.Time
	for _, cert := range certs {
		c, e := x509.ParseCertificate(cert.Certificate[0])
		if e == nil {
			notAfter = c.NotAfter
			break
		}
	}
	return notAfter
}

// helper function to send email
func sendEmail(to, body string) {
	toList := []string{to}
	if strings.Contains(to, ",") {
		toList = strings.Split(to, ",")
	}
	host := "smtp.gmail.com"
	port := "587"
	from := os.Getenv("MAIL")
	password := os.Getenv("PASSWD")
	auth := smtp.PlainAuth("", from, password, host)
	err := smtp.SendMail(host+":"+port, auth, from, toList, []byte(body))
	if err != nil {
		log.Fatal(err)
	}
}

// helper function to send notification
func sendNotification(apiURL, msg, token string) {
	if apiURL == "" {
		log.Fatal("Unable to POST request to empty URL, please provide valid URL for alert option")
	}
	var headers [][]string
	bearer := fmt.Sprintf("Bearer %s", token)
	headers = append(headers, []string{"Authorization", bearer})
	headers = append(headers, []string{"Content-Type", "application/json"})
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(msg)))
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range headers {
		if len(v) == 2 {
			req.Header.Set(v[0], v[1])
		}
	}
	timeout := time.Duration(1) * time.Second
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		log.Printf("Unable to send notication to %s", apiURL)
		return
	}
}
