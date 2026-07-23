# Usage

```bash
go get github.com/andreyfesunov/awswaf@latest
```

```go
package main

import (
	"log"

	"github.com/andreyfesunov/awswaf"
)

func main() {
	// host & gokuProps come from the challenge HTML page
	goku, host, err := awswaf.Extract(html)
	if err != nil {
		log.Fatal(err)
	}

	// challengeJS can be "" to use defaults; proxy can be "" for direct
	waf, err := awswaf.NewWaf(
		host,
		"www.example.com",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		goku,
		challengeJS,
		proxy,
		120,
	)
	if err != nil {
		log.Fatal(err)
	}

	token, err := waf.Run()
	if err != nil {
		log.Fatal(err)
	}
	// token is the aws-waf-token cookie value
	_ = token
}
```
