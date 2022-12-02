# cert-checker

Certificate checker

### How to

```
go build main.go config.go
./main -config config.json -team "monitoring" -httpPort 8888

#
$ curl 127.0.0.1:8888/metrics
# HELP cert_valid_sec
# TYPE cert_valid_sec gauge
cert_valid_sec{file_name="usercert.pem", common_name="<CN Name>" team="monitoring"} 1.2230344333986e+07
# HELP keytab_valid_sec
# TYPE keytab_valid_sec gauge
keytab_valid_sec{file_name="keytab", principle="<Keytab principle name>", team="monitoring"} 3.0477057333219e+07

```
