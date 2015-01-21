package jwks

import (
	"log"
	"testing"
	"time"
)

const GoogleKeyStoreUrl = "https://www.googleapis.com/oauth2/v2/certs"
const TestGoogleToken = "FIXME: Write some real tests!"

func TestJsonKeyStore(t *testing.T) {
	keyStore := New(GoogleKeyStoreUrl, 0)
	for i := 0; i < 10; i++ {
		claims, err := keyStore.Verify(TestGoogleToken)
		if err != nil {
			log.Printf("Verification error: %s", err)
		} else {
			log.Printf("Token verified. Claims: %+v", claims)
		}
		switch i {
		case 1:
			keyStore.SetUpdateInterval(time.Second / 2)
		case 4:
			keyStore.SetUpdateInterval(0)
		case 6:
			keyStore.SetUpdateInterval(time.Second / 2)
		case 9:
			keyStore.SetUpdateInterval(0)
		}
		time.Sleep(1 * time.Second)
	}
}
