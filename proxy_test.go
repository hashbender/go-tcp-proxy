package proxy

import (
	"strings"
	"testing"
)

func TestAuthorizeReplace(t *testing.T) {
	b := []byte("{\"id\":3,\"method\":\"mining.authorize\",\"params\":[\"selfmining.minerA\",\"x\"]}")
	authStr := string(b)
	//
	idx := strings.Index(authStr, "[\"") + 2
	lastIdx := idx
	for i := idx; i < len(authStr); i++ {
		if authStr[i] == '"' {
			lastIdx = i
			break
		}
	}
	newStr := authStr[:idx] + "selfmining.random_string" + authStr[lastIdx:]
	t.Errorf("output2 %s", newStr)
}
