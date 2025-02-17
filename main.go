package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	urlFlag     = flag.String("u", "", "Test a single domain")
	listFlag    = flag.String("l", "", "List of subdomains")
	threadsFlag = flag.Int("t", 100, "Number of threads (default: 100)")
	timeoutFlag = flag.Int("time", 30, "Timeout in seconds (default: 30)")
	outputFlag  = flag.String("o", "", "Output file (txt or json)")
	sslFlag     = flag.Bool("ssl", false, "Skip invalid SSL sites")
	httpsFlag   = flag.Bool("https", false, "Use HTTPS by default")
	allRequests = flag.Bool("a", false, "Skip CNAME check, send requests to every URL")
	deadRecord  = flag.Bool("m", false, "Flag dead records but valid CNAME entries")
	hideFailed  = flag.Bool("hide", false, "Hide failed checks and invulnerable subdomains")
	cnameFlag   = flag.Bool("cname", false, "Print detailed CNAME information")
	errorFlag   = flag.Bool("error", false, "Hide errors and failed requests")
)

// Pre-defined mapping of known CNAME components to their respective service names.
var service_mapping = map[string]string{
	"github.io":                            "GitHub Pages",
	"herokuapp.com":                        "Heroku",
	"s3.amazonaws.com":                     "AWS S3",
	"netlify.app":                          "Netlify",
	"execute-api":                          "API Gateway",
	"appspot.com":                          "Google App Engine",
	"wordpress.com":                        "WordPress",
	"bitbucket.io":                         "Bitbucket Pages",
	"backblazeb2.com":                      "Backblaze B2",
	"wasabisys.com":                        "Wasabi Cloud Storage",
	"scw.cloud":                            "Scaleway Object Storage",
	"myqcloud.com":                         "Tencent Cloud COS",
	"cloud-object-storage.appdomain.cloud": "IBM Cloud Object Storage",
	"ghost.io":                             "Ghost",
	"nationbuilder.com":                    "NationBuilder",
	"cargocollective.com":                  "Cargo Collective",
	"format.com":                           "Format",
	"smugmug.com":                          "SmugMug",
	"weebly.com":                           "Weebly",
	"yolasite.com":                         "Yola",
	"squarespace.com":                      "Squarespace",
	"websitebuilder.online":                "1&1 IONOS",
	"surge.sh":                             "Surge.sh",
	"infinityfreeapp.com":                  "InfinityFree",
	"onrender.com":                         "Render",
	"web.app":                              "Firebase Hosting",
	"gitbook.io":                           "GitBook",
	"expo.dev":                             "Expo",
	"glideapp.io":                          "GlideApps",
	"divshot.io":                           "Divshot",
	"beanstalkapp.com":                     "Beanstalk",
	"freshservice.com":                     "Freshservice",
	"groovehq.com":                         "GrooveHQ",
	"kayako.com":                           "Kayako",
	"livechatinc.com":                      "LiveChat",
	"ticksy.com":                           "Ticksy",
	"uservoice.com":                        "UserVoice",
	"tenderapp.com":                        "TenderApp",
	"launchrock.com":                       "LaunchRock",
	"surveymonkey.com":                     "SurveyMonkey",
	"formstack.com":                        "FormStack",
	"trello.com":                           "Trello",
	"clubhouse.io":                         "Clubhouse.io",
	"asana.com":                            "Asana",
	"basecamphq.com":                       "Basecamp",
	"unbounce.com":                         "Unbounce",
	"hubspot.net":                          "HubSpot",
	"marketo.com":                          "Marketo",
	"clickfunnels.com":                     "ClickFunnels",
	"instapage.com":                        "Instapage",
	"optimizely.com":                       "Optimizely",
	"hotjar.com":                           "Hotjar",
	"docsify.io":                           "Docsify",
	"mkdocs.org":                           "MkDocs",
	"hexo.io":                              "Hexo",
	"gitkraken.com":                        "GitKraken",
	"bookstackapp.com":                     "BookStack",
	"disqus.com":                           "Disqus",
	"vanillaforums.com":                    "Vanilla Forums",
	"muut.com":                             "Muut",
	"xenforo.com":                          "XenForo",
	"ecwid.com":                            "Ecwid",
	"gumroad.com":                          "Gumroad",
	"lemonstand.com":                       "LemonStand",
	"payhip.com":                           "Payhip",
	"firebaseapp.com":                      "Firebase Hosting",
	"ghost.org":                            "Ghost",
	"unbouncepages.com":                    "Unbounce Page",
	"mailgun.org":                          "Mailgun ORG",
	"cloudfront.net": "Amazon CloudFront",
        "fastly.net": "Fastly CDN",
    "incapdns.net": "Imperva Incapsula",
    "cloudflare.net": "Cloudflare",
    "herokudns.com": "Heroku DNS",
    "pages.dev": "Cloudflare Pages",
    "pantheonsite.io": "Pantheon",
    "fly.dev": "Fly.io",
    "azurewebsites.net": "Azure Websites",
    "azurefd.net": "Azure Front Door",
    "wordpressvip.com": "WordPress VIP",
    "akamai.net": "Akamai",
    "edgesuite.net": "Akamai Edge",
    "llnwd.net": "Limelight Networks",
    "rackcdn.com": "Rackspace Cloud Files",
    "netdna-cdn.com": "NetDNA CDN",
    "stackpathdns.com": "StackPath",
    "atlassian.net": "Atlassian",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "HelpScout",
    "intercom.io": "Intercom",
    "statuspage.io": "StatusPage",
    "freshdesk.com": "Freshdesk",
    "loggly.com": "Loggly",
    "papertrailapp.com": "Papertrail",
    "datadoghq.com": "Datadog",
    "newrelic.com": "New Relic",
    "rollbar.com": "Rollbar",
    "sentry.io": "Sentry",
    "bugsnag.com": "Bugsnag",
    "raygun.io": "Raygun",
    "zapier.com": "Zapier",
    "slack.com": "Slack",
    "discord.com": "Discord",
    "streamlitapp.com": "Streamlit",
    "repl.co": "Replit",
    "glitch.me": "Glitch",
    "codesandbox.io": "CodeSandbox",
    "codepen.io": "CodePen",
    "jsfiddle.net": "JSFiddle",
    "cloudinary.com": "Cloudinary",
    "imgur.com": "Imgur",
    "tumblr.com": "Tumblr",
    "jotform.com": "JotForm",
    "formsite.com": "Formsite",
    "surveygizmo.com": "SurveyGizmo",
    "smartsheet.com": "Smartsheet",
    "monday.com": "Monday.com",
    "basekit.com": "BaseKit",
    "zoho.com": "Zoho",
    "wixsite.com": "Wix",
    "blogspot.com": "Blogger",
    "jimdo.com": "Jimdo",
    "site123.me": "SITE123",
    "webnode.com": "Webnode",
    "ucraft.com": "Ucraft",
    "duda.co": "Duda",
    "strikingly.com": "Strikingly",
    "webflow.io": "Webflow",
    "readymag.com": "Readymag",

  
    "cdn77.com": "CDN77",
    "cachefly.net": "CacheFly",
    "edgecastcdn.net": "EdgeCast",
    "maxcdn.com": "MaxCDN",
    "cdn.jsdelivr.net": "jsDelivr",
    "unpkg.com": "unpkg",
    "akamaihd.net": "Akamai HD",
    "keycdn.com": "KeyCDN",
    "stackpathcdn.com": "StackPath CDN",
    "cotcdn.net": "Cotendo CDN",

  
    "cloudwaysapps.com": "Cloudways",
    "liara.run": "Liara",
    "carrd.co": "Carrd",
    "scalingo.com": "Scalingo",
    "c9users.io": "Cloud9",
    "000webhostapp.com": "000Webhost",
    "deta.dev": "Deta",
    "nexcess.net": "Nexcess",
    "koyeb.app": "Koyeb",
    "vercel.app": "Vercel",
}

type Result struct {
	Subdomain string `json:"subdomain"`
	Status    string `json:"status"`
	CNAME     string `json:"cname,omitempty"`
}

var clientPool = sync.Pool{
	New: func() interface{} {
		return &http.Client{Timeout: time.Duration(*timeoutFlag) * time.Second}
	},
}

var mu sync.Mutex

// Fingerprint represents a service fingerprint from the external JSON.
type Fingerprint struct {
	CNAME   []string `json:"cname"`
	Service string   `json:"service"`
}

// loadExternalServices fetches service fingerprints from the given URL and merges them into service_mapping.
func loadExternalServices(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error loading external services: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var fingerprints []Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&fingerprints); err != nil {
		fmt.Printf("Error decoding external services: %v\n", err)
		return
	}
	for _, fp := range fingerprints {
		for _, cname := range fp.CNAME {
			key := strings.ToLower(strings.TrimSuffix(cname, "."))
			if key != "" && fp.Service != "" {
				service_mapping[key] = fp.Service
			}
		}
	}
}

// printDetailedInfo displays a structured output for each subdomain.
func printDetailedInfo(subdomain, url string, resp *http.Response, cname, service string, takeover bool) {
	line := "--------------------------------------------------"
	if takeover {
		color.Red(line)
		color.Red("Subdomain: %s", subdomain)
		color.Red("URL:       %s", url)
		color.Red("Status:    %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		color.Red("CNAME:     %s", cname)
		color.Red("Service:   %s", service)
		color.Red(line)
	} else {
		color.Green(line)
		color.Green("Subdomain: %s", subdomain)
		color.Green("URL:       %s", url)
		color.Green("Status:    %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		color.Green("CNAME:     %s", cname)
		color.Green("Service:   %s", service)
		color.Green(line)
	}
}

// getServiceFromSubdomain performs a case-insensitive check of the provided string against our service_mapping.
func getServiceFromSubdomain(s string) string {
	ls := strings.ToLower(s)
	for key, service := range service_mapping {
		if strings.Contains(ls, key) {
			return service
		}
	}
	return "Unknown"
}

func checkSubdomain(subdomain string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	// Construct URL using HTTP or HTTPS based on the flag.
	url := subdomain
	if *httpsFlag {
		url = "https://" + subdomain
	} else {
		url = "http://" + subdomain
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		if !*errorFlag {
			mu.Lock()
			color.Red("[ERROR] %s - Failed to create request: %v", subdomain, err)
			mu.Unlock()
		}
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		if !*errorFlag {
			mu.Lock()
			color.Red("[ERROR] %s - Request failed: %v", subdomain, err)
			mu.Unlock()
		}
		return
	}
	defer resp.Body.Close()

	// Lookup the CNAME record.
	var cname string
	var cnameRecords string
	if cnameRecordsTmp, err := net.LookupCNAME(subdomain); err == nil && cnameRecordsTmp != "" {
		cnameRecords = cnameRecordsTmp
		cname = fmt.Sprintf("%s -> %s", subdomain, cnameRecordsTmp)
	} else {
		cname = "No CNAME record found"
	}

	// Use the CNAME (if available) for service detection.
	lookupStr := subdomain
	if cnameRecords != "" {
		lookupStr = strings.TrimSuffix(cnameRecords, ".")
	}
	service := getServiceFromSubdomain(lookupStr)

	mu.Lock()
	defer mu.Unlock()

	// Mark as potential takeover if HTTP status is 404.
	if resp.StatusCode == 404 {
		printDetailedInfo(subdomain, url, resp, cname, service, true)
		results <- Result{Subdomain: subdomain, Status: "Potential Takeover", CNAME: cname}
	} else {
		if !*hideFailed {
			printDetailedInfo(subdomain, url, resp, cname, service, false)
			results <- Result{
				Subdomain: subdomain,
				Status:    fmt.Sprintf("%d %s - %s", resp.StatusCode, http.StatusText(resp.StatusCode), service),
				CNAME:     cname,
			}
		}
	}
}

func main() {
	flag.Parse()

	// Load external service fingerprints from the provided JSON URL.
	loadExternalServices("https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json")

	var subdomains []string
	if *urlFlag != "" {
		subdomains = append(subdomains, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			color.Red("Error opening file: %v", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomains = append(subdomains, strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			color.Red("Error reading file: %v", err)
			return
		}
	}

	results := make(chan Result, len(subdomains))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *threadsFlag)

	for _, subdomain := range subdomains {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(sd string) {
			defer func() { <-semaphore }()
			checkSubdomain(sd, results, &wg)
		}(subdomain)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Output results to a file if specified; otherwise, results are printed to the console.
	outputFile := *outputFlag
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			color.Red("Error creating output file: %v", err)
			return
		}
		defer file.Close()

		if strings.HasSuffix(outputFile, ".json") {
			jsonEncoder := json.NewEncoder(file)
			jsonEncoder.SetIndent("", "  ")
			file.WriteString("[")
			first := true
			for res := range results {
				if !first {
					file.WriteString(",")
				}
				jsonEncoder.Encode(res)
				first = false
			}
			file.WriteString("]")
		} else {
			for res := range results {
				file.WriteString(fmt.Sprintf("%s - %s\n", res.Subdomain, res.Status))
			}
		}
	} else {
		for range results {
			// Detailed output is already printed.
		}
	}
}
