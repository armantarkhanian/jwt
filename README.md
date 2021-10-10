# Example
```golang
package main

import (
	"fmt"
	"time"

	"github.com/armantarkhanian/jwt"
)

type CustomPayload struct {
	jwt.Payload
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
}

func main() {
	payload := CustomPayload{
		Payload: jwt.Payload{
			Subject:        "42",
			ExpirationTime: time.Now().UTC().Add(48 * time.Hour).Unix(),
		},
		Username: "test user",
	}

	ed, err := jwt.NewEncodeDecoder("SECRET_KEY SECRET_KEY SECRET_KEY SECRET_KEY SECRET_KEY SECRET_KEY")
	if err != nil {
		panic(err)
	}

	token, err := ed.Encode(payload)
	if err != nil {
		panic(err)
	}

	var newPayload CustomPayload
	err = ed.Decode(token, &newPayload)
	if err != nil {
		panic(err)
	}

	fmt.Println(payload)    // {{ 42 [] 1634041647 0 0 } test user }
	fmt.Println(token)      // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImV4cCI6MTYzNDA0MTcxMCwidXNlcm5hbWUiOiJ0ZXN0IHVzZXIifQ.IyLIswzRjh3XfQv65FXzXAjjUwNS46Fk6YUe0k0Gs48
	fmt.Println(newPayload) // {{ 42 [] 1634041647 0 0 } test user }
}
```
