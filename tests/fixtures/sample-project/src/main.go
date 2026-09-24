package main

import (
	"fmt"
	"net/http"
)

const twilioAccountSID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxx000000" // fake SID for testing
const twilioAuthToken = "abc123def456abc123def456abc12345"

func main() {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://api.twilio.com", nil)
	req.SetBasicAuth(twilioAccountSID, twilioAuthToken)
	resp, _ := client.Do(req)
	fmt.Println(resp.Status)
}
