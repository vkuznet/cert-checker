package main

// configuration module for cert-checker
//
// Copyright (c) 2022 - Valentin Kuznetsov <vkuznet AT gmail dot com>
//
import (
	"encoding/json"
	"log"
	"os"
)

type Configuration struct {
	Keytab string `json:"keytab,omitempty"` // keytab file
	Cert   string `json:"cert,omitempty"`   // certificate public file
	Ckey   string `json:"ckey,omitempty"`   // certificate private file
}

// Configs represents user provided certs and keytab files
var Configs []Configuration

// String returns string representation of dbs Configs
func (c *Configuration) String() string {
	data, err := json.Marshal(c)
	if err != nil {
		log.Println("ERROR: fail to marshal configuration", err)
		return ""
	}
	return string(data)
}

// ParseConfig parses given configuration file and initialize Configs object
func ParseConfig(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Println("unable to read config file", configFile, err)
		return err
	}
	err = json.Unmarshal(data, &Configs)
	if err != nil {
		log.Println("unable to parse config file", configFile, err)
		return err
	}
	return nil
}
