package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
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

func main() {
	var cert string
	flag.StringVar(&cert, "cert", "", "file certificate (PEM file name)")
	var ckey string
	flag.StringVar(&ckey, "ckey", "", "file certficate private key (PEM file name)")
	var alert string
	flag.StringVar(&alert, "alert", "", "alert email or URL")
	var interval int
	flag.IntVar(&interval, "interval", 600, "interval before expiration (in seconds)")
	var version bool
	flag.BoolVar(&version, "version", false, "print version information about the server")
	flag.Parse()
	if version {
		fmt.Println(info())
		os.Exit(0)
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	check(cert, ckey, alert, interval)
}

func check(cert, ckey, alert string, interval int) {
	certs, err := getCert(cert, ckey)
	if err != nil {
		log.Fatalf("Unable to read certificate cert=%s, ckey=%s, error=%v", cert, ckey, err)
	}
	tsCert := CertExpire(certs)
	ts := time.Now().Add(time.Duration(interval) * time.Second)
	if tsCert.Before(ts) {
		log.Printf("ALERT: certificate timestamp: %v, timestamp: %v, alert %s", tsCert, ts, alert)
	} else {
		log.Printf("Certificate %s expires on %v, well after interval=%d (sec) or %v", cert, tsCert, interval, ts)
	}

}

func getCert(cert, ckey string) ([]tls.Certificate, error) {
	var x509cert tls.Certificate
	var err error
	if cert != "" && ckey != "" {
		x509cert, err = tls.LoadX509KeyPair(cert, ckey)
	} else {
		x509cert, err = x509proxy.LoadX509Proxy(cert)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 proxy: %v", err)
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
