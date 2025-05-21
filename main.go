package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"github.com/schollz/progressbar/v3"
	"github.com/slack-go/slack"
	"gopkg.in/yaml.v3"
	_ "github.com/mattn/go-sqlite3"
)

// Version information
const (
	VERSION = "2.0.0"
	BANNER  = `
   _____       __    _  __
  / ___/__  __/ /_  | |/_/
  \__ \/ / / / __ \_>  <  
 ___/ / /_/ / /_/ /_/|  | 
/____/\__,_/_.___//_/|_|  v%s
                          
`
)

// Enhanced Result struct with more detailed information
type Result struct {
	Subdomain       string            `json:"subdomain"`
	Status          string            `json:"status"`
	StatusCode      int               `json:"status_code,omitempty"`
	CNAME           string            `json:"cname,omitempty"`
	Service         string            `json:"service,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	TakeoverPossible bool              `json:"takeover_possible"`
	RiskLevel       string            `json:"risk_level,omitempty"` // high, medium, low
	ScreenshotPath  string            `json:"screenshot_path,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	Verification    string            `json:"verification,omitempty"` // verified, unverified, failed
}

// Configuration represents the YAML/JSON configuration file structure
type Configuration struct {
	General struct {
		Threads      int     `yaml:"threads" json:"threads"`
		Timeout      int     `yaml:"timeout" json:"timeout"`
		RateLimit    float64 `yaml:"rate_limit" json:"rate_limit"`
		AdaptiveRate bool    `yaml:"adaptive_rate" json:"adaptive_rate"`
		UserAgent    string  `yaml:"user_agent" json:"user_agent"`
		Verbose      int     `yaml:"verbose" json:"verbose"`
	} `yaml:"general" json:"general"`
	
	Input struct {
		URL  string `yaml:"url" json:"url"`
		List string `yaml:"list" json:"list"`
	} `yaml:"input" json:"input"`
	
	Output struct {
		File        string `yaml:"file" json:"file"`
		Format      string `yaml:"format" json:"format"`
		HideFailed  bool   `yaml:"hide_failed" json:"hide_failed"`
		HideErrors  bool   `yaml:"hide_errors" json:"hide_errors"`
		ShowCNAME   bool   `yaml:"show_cname" json:"show_cname"`
	} `yaml:"output" json:"output"`
	
	Network struct {
		HTTPS       bool   `yaml:"https" json:"https"`
		SkipSSL     bool   `yaml:"skip_ssl" json:"skip_ssl"`
		Proxy       string `yaml:"proxy" json:"proxy"`
		DNSServer   string `yaml:"dns_server" json:"dns_server"`
		DoH         string `yaml:"doh" json:"doh"`
		RespectRobots bool `yaml:"respect_robots" json:"respect_robots"`
	} `yaml:"network" json:"network"`
	
	Features struct {
		Screenshots      bool   `yaml:"screenshots" json:"screenshots"`
		ScreenshotDir    string `yaml:"screenshot_dir" json:"screenshot_dir"`
		Database         string `yaml:"database" json:"database"`
		API              bool   `yaml:"api" json:"api"`
		APIPort          int    `yaml:"api_port" json:"api_port"`
		WebUI            bool   `yaml:"web_ui" json:"web_ui"`
		WebPort          int    `yaml:"web_port" json:"web_port"`
		Resumable        bool   `yaml:"resumable" json:"resumable"`
		ResumeFile       string `yaml:"resume_file" json:"resume_file"`
		PluginDir        string `yaml:"plugin_dir" json:"plugin_dir"`
		Interactive      bool   `yaml:"interactive" json:"interactive"`
		Distributed      bool   `yaml:"distributed" json:"distributed"`
		Master           string `yaml:"master" json:"master"`
		Worker           bool   `yaml:"worker" json:"worker"`
		WorkerPort       int    `yaml:"worker_port" json:"worker_port"`
	} `yaml:"features" json:"features"`
	
	Notifications struct {
		Slack   string `yaml:"slack" json:"slack"`
		Discord string `yaml:"discord" json:"discord"`
		Email   string `yaml:"email" json:"email"`
		SMTP    struct {
			Server   string `yaml:"server" json:"server"`
			Username string `yaml:"username" json:"username"`
			Password string `yaml:"password" json:"password"`
		} `yaml:"smtp" json:"smtp"`
	} `yaml:"notifications" json:"notifications"`
}

// Fingerprint represents a service fingerprint from the external JSON.
type Fingerprint struct {
	CNAME   []string `json:"cname"`
	Service string   `json:"service"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []string `json:"body,omitempty"`
	Status  []int    `json:"status,omitempty"`
	Regex   []string `json:"regex,omitempty"`
	Risk    string   `json:"risk,omitempty"`
}

// DNSCache provides a simple in-memory cache for DNS lookups
type DNSCache struct {
	cache map[string][]string
	mu    sync.RWMutex
	ttl   time.Duration
}

// RateLimiter manages request rates
type RateLimiter struct {
	rate       float64
	adaptive   bool
	bucket     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// Plugin represents a detection plugin
type Plugin struct {
	Name        string
	Description string
	Version     string
	Author      string
	Execute     func(subdomain string, client *http.Client) (bool, string, string)
}

// Global variables for new features
var (
	config         Configuration
	dnsCache       *DNSCache
	rateLimiter    *RateLimiter
	db             *sql.DB
	fingerprints   []Fingerprint
	plugins        []Plugin
	progressBar    *progressbar.ProgressBar
	resumeState    map[string]bool
	httpClient     *http.Client
	logger         *log.Logger
	robotsCache    map[string]bool
	debugStats     *ScanStats
)

// ScanStats tracks statistics for debugging and reporting
type ScanStats struct {
	StartTime          time.Time
	EndTime            time.Time
	TotalDomains       int
	ProcessedDomains   int
	VulnerableDomains  int
	ErrorCount         int
	TotalRequests      int
	CacheHits          int
	AverageResponseTime time.Duration
	ResponseTimes      []time.Duration
	mu                 sync.Mutex
}

// NewScanStats creates a new ScanStats instance
func NewScanStats(totalDomains int) *ScanStats {
	return &ScanStats{
		StartTime:     time.Now(),
		TotalDomains:  totalDomains,
		ResponseTimes: make([]time.Duration, 0, totalDomains),
	}
}

// IncrementProcessed increments the processed domains counter
func (s *ScanStats) IncrementProcessed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProcessedDomains++
}

// IncrementVulnerable increments the vulnerable domains counter
func (s *ScanStats) IncrementVulnerable() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VulnerableDomains++
}

// IncrementErrors increments the error counter
func (s *ScanStats) IncrementErrors() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ErrorCount++
}

// IncrementRequests increments the total requests counter
func (s *ScanStats) IncrementRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRequests++
}

// IncrementCacheHits increments the cache hits counter
func (s *ScanStats) IncrementCacheHits() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CacheHits++
}

// AddResponseTime adds a response time to the list and updates the average
func (s *ScanStats) AddResponseTime(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ResponseTimes = append(s.ResponseTimes, d)
	
	// Recalculate average
	var total time.Duration
	for _, t := range s.ResponseTimes {
		total += t
	}
	s.AverageResponseTime = total / time.Duration(len(s.ResponseTimes))
}

// Finish marks the scan as finished and sets the end time
func (s *ScanStats) Finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndTime = time.Now()
}

// GetStats returns a map of statistics
func (s *ScanStats) GetStats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	duration := s.EndTime
	if duration.IsZero() {
		duration = time.Now()
	}
	
	return map[string]interface{}{
		"total_domains":        s.TotalDomains,
		"processed_domains":   s.ProcessedDomains,
		"vulnerable_domains":  s.VulnerableDomains,
		"error_count":         s.ErrorCount,
		"total_requests":      s.TotalRequests,
		"cache_hits":          s.CacheHits,
		"average_response_ms": s.AverageResponseTime.Milliseconds(),
		"duration_seconds":   duration.Sub(s.StartTime).Seconds(),
		"domains_per_second": float64(s.ProcessedDomains) / duration.Sub(s.StartTime).Seconds(),
	}
}

// debugPrint prints debug information if verbose level is high enough
func debugPrint(level int, format string, args ...interface{}) {
	if *verboseFlag >= level {
		logger.Printf(format, args...)
	}
}

// traceTiming is used to trace function execution time
func traceTiming(functionName string) func() {
	if *verboseFlag < 3 {
		return func() {}
	}
	
	start := time.Now()
	logger.Printf("TRACE: Entering %s", functionName)
	return func() {
		logger.Printf("TRACE: Exiting %s (took %v)", functionName, time.Since(start))
	}
}

var (
	// Basic flags
	urlFlag     = flag.String("u", "", "Test a single domain")
	listFlag    = flag.String("l", "", "List of subdomains")
	threadsFlag = flag.Int("t", 100, "Number of threads (default: 100)")
	timeoutFlag = flag.Int("time", 30, "Timeout in seconds (default: 30)")
	outputFlag  = flag.String("o", "", "Output file (txt, json, csv, or html)")
	sslFlag     = flag.Bool("ssl", false, "Skip invalid SSL sites")
	httpsFlag   = flag.Bool("https", false, "Use HTTPS by default")
	allRequests = flag.Bool("a", false, "Skip CNAME check, send requests to every URL")
	deadRecord  = flag.Bool("m", false, "Flag dead records but valid CNAME entries")
	hideFailed  = flag.Bool("hide", false, "Hide failed checks and invulnerable subdomains")
	cnameFlag   = flag.Bool("cname", false, "Print detailed CNAME information")
	errorFlag   = flag.Bool("error", false, "Hide errors and failed requests")
	
	// New flags for enhanced features
	configFlag        = flag.String("config", "", "Path to configuration file (YAML/JSON)")
	verboseFlag       = flag.Int("v", 1, "Verbosity level (0-3)")
	proxyFlag         = flag.String("proxy", "", "Proxy URL (e.g., socks5://127.0.0.1:9050)")
	userAgentFlag     = flag.String("ua", "SubX/2.0", "Custom User-Agent string")
	rateLimitFlag     = flag.Float64("rate", 10.0, "Maximum requests per second")
	adaptiveRateFlag  = flag.Bool("adaptive-rate", false, "Enable adaptive rate limiting")
	dnsServerFlag     = flag.String("dns", "", "Custom DNS server (e.g., 8.8.8.8:53)")
	dohFlag           = flag.String("doh", "", "DNS over HTTPS server URL")
	screenshotFlag    = flag.Bool("screenshot", false, "Capture screenshots of vulnerable domains")
	screenshotDirFlag = flag.String("screenshot-dir", "./screenshots", "Directory to save screenshots")
	dbPathFlag        = flag.String("db", "./subx.db", "Path to SQLite database for historical data")
	apiFlag           = flag.Bool("api", false, "Start RESTful API server")
	apiPortFlag       = flag.Int("api-port", 8080, "Port for API server")
	webUIFlag         = flag.Bool("web", false, "Start web UI")
	webPortFlag       = flag.Int("web-port", 8081, "Port for web UI")
	slackWebhookFlag  = flag.String("slack", "", "Slack webhook URL for notifications")
	discordWebhookFlag = flag.String("discord", "", "Discord webhook URL for notifications")
	emailFlag         = flag.String("email", "", "Email address for notifications")
	smtpServerFlag    = flag.String("smtp", "", "SMTP server for email notifications")
	smtpUserFlag      = flag.String("smtp-user", "", "SMTP username")
	smtpPassFlag      = flag.String("smtp-pass", "", "SMTP password")
	resumableFlag     = flag.Bool("resumable", false, "Enable resumable scanning")
	resumeFileFlag    = flag.String("resume-file", "./subx-resume.json", "File to store resumable scan state")
	pluginDirFlag     = flag.String("plugin-dir", "./plugins", "Directory containing detection plugins")
	respectRobotsFlag = flag.Bool("respect-robots", false, "Respect robots.txt directives")
	interactiveFlag   = flag.Bool("interactive", false, "Enable interactive mode")
	distributedFlag   = flag.Bool("distributed", false, "Enable distributed scanning")
	masterFlag        = flag.String("master", "", "Master node address for distributed scanning")
	workerFlag        = flag.Bool("worker", false, "Run as worker node for distributed scanning")
	workerPortFlag    = flag.Int("worker-port", 8082, "Port for worker node")
	
	// Update and upgrade flags
	updateFlag        = flag.Bool("update", false, "Check for updates to SubX")
	upgradeFlag       = flag.Bool("upgrade", false, "Automatically upgrade SubX to the latest version")
	updateURLFlag     = flag.String("update-url", "https://api.github.com/repos/Karthikdude/SubX/releases/latest", "URL to check for updates")
	forceUpdateFlag   = flag.Bool("force-update", false, "Force update even if current version is up to date")
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
	Headers map[string]string `json:"headers,omitempty"`
	Body    []string `json:"body,omitempty"`
	Status  []int    `json:"status,omitempty"`
	Regex   []string `json:"regex,omitempty"`
	Risk    string   `json:"risk,omitempty"`
}

// loadExternalServices fetches service fingerprints from the given URL and merges them into service_mapping.
func loadExternalServices(url string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		if *verboseFlag > 0 {
			logger.Printf("Warning: Could not fetch external fingerprints: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	var fps []Fingerprint
	if err := json.NewDecoder(resp.Body).Decode(&fps); err != nil {
		if *verboseFlag > 0 {
			logger.Printf("Warning: Could not parse external fingerprints: %v", err)
		}
		return
	}

	// Add to our fingerprints slice
	fingerprints = append(fingerprints, fps...)

	// Also update the service_mapping for backward compatibility
	for _, fp := range fps {
		for _, cname := range fp.CNAME {
			service_mapping[strings.ToLower(cname)] = fp.Service
		}
	}

	if *verboseFlag > 1 {
		logger.Printf("Loaded %d external fingerprints", len(fps))
	}
}

// initLogger initializes the logging system
func initLogger() {
	logLevel := "INFO"
	switch *verboseFlag {
	case 0:
		logLevel = "ERROR"
	case 1:
		logLevel = "INFO"
	case 2:
		logLevel = "DEBUG"
	case 3:
		logLevel = "TRACE"
	}

	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("logs", 0755); err != nil {
		fmt.Printf("Error creating logs directory: %v\n", err)
	}

	// Create log file with timestamp
	logFileName := fmt.Sprintf("logs/subx_%s.log", time.Now().Format("2006-01-02_15-04-05"))
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		logger = log.New(os.Stderr, fmt.Sprintf("[SubX %s] ", logLevel), log.LstdFlags)
	} else {
		// Create multi-writer to write to both stderr and file
		multiWriter := io.MultiWriter(os.Stderr, logFile)
		logger = log.New(multiWriter, fmt.Sprintf("[SubX %s] ", logLevel), log.LstdFlags|log.Lshortfile)
	}

	logger.Printf("SubX v%s logging initialized at level %s", VERSION, logLevel)
	logger.Printf("Log file: %s", logFileName)
}

// initHTTPClient initializes the HTTP client with custom settings
func initHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !*sslFlag},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	// Configure proxy if specified
	if *proxyFlag != "" {
		proxyURL, err := url.Parse(*proxyFlag)
		if err != nil {
			logger.Printf("Error parsing proxy URL: %v", err)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutFlag) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Update the client pool
	clientPool = sync.Pool{
		New: func() interface{} {
			return httpClient
		},
	}
}

// initDNSCache initializes the DNS cache
func initDNSCache() {
	dnsCache = &DNSCache{
		cache: make(map[string][]string),
		ttl:   time.Hour, // Cache DNS results for 1 hour
	}
}

// initRateLimiter initializes the rate limiter
func initRateLimiter() {
	rateLimiter = &RateLimiter{
		rate:       *rateLimitFlag,
		adaptive:   *adaptiveRateFlag,
		bucket:     *rateLimitFlag,
		lastUpdate: time.Now(),
	}
}

// initDatabase initializes the SQLite database for historical data
func initDatabase() error {
	var err error
	db, err = sql.Open("sqlite3", *dbPathFlag)
	if err != nil {
		return err
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			description TEXT
		);
		
		CREATE TABLE IF NOT EXISTS results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER,
			subdomain TEXT,
			status TEXT,
			status_code INTEGER,
			cname TEXT,
			service TEXT,
			takeover_possible BOOLEAN,
			risk_level TEXT,
			verification TEXT,
			timestamp DATETIME,
			FOREIGN KEY (scan_id) REFERENCES scans(id)
		);
	`)
	return err
}

// loadConfig loads configuration from a YAML/JSON file
func loadConfig(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	// Determine if it's JSON or YAML based on file extension
	if strings.HasSuffix(path, ".json") {
		return json.Unmarshal(data, &config)
	} else {
		return yaml.Unmarshal(data, &config)
	}
}

// applyConfig applies the loaded configuration to the flags
func applyConfig() {
	// Only override flags that weren't explicitly set on the command line
	flag.Visit(func(f *flag.Flag) {
		// Mark this flag as explicitly set
		// We'll skip overriding these flags
	})

	// Apply configuration to flags that weren't explicitly set
	if config.General.Threads > 0 {
		flag.Set("t", fmt.Sprintf("%d", config.General.Threads))
	}
	if config.General.Timeout > 0 {
		flag.Set("time", fmt.Sprintf("%d", config.General.Timeout))
	}
	if config.General.RateLimit > 0 {
		flag.Set("rate", fmt.Sprintf("%f", config.General.RateLimit))
	}
	if config.General.UserAgent != "" {
		flag.Set("ua", config.General.UserAgent)
	}
	// ... and so on for all other config options
}

// loadPlugins loads detection plugins from the plugin directory
func loadPlugins() error {
	if *pluginDirFlag == "" {
		return nil
	}

	files, err := ioutil.ReadDir(*pluginDirFlag)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			data, err := ioutil.ReadFile(filepath.Join(*pluginDirFlag, file.Name()))
			if err != nil {
				logger.Printf("Error reading plugin %s: %v", file.Name(), err)
				continue
			}

			var plugin Plugin
			if err := json.Unmarshal(data, &plugin); err != nil {
				logger.Printf("Error parsing plugin %s: %v", file.Name(), err)
				continue
			}

			plugins = append(plugins, plugin)
			logger.Printf("Loaded plugin: %s v%s by %s", plugin.Name, plugin.Version, plugin.Author)
		}
	}

	return nil
}

// loadResumeState loads the state of a previously interrupted scan
func loadResumeState() error {
	if !*resumableFlag || *resumeFileFlag == "" {
		return nil
	}

	data, err := ioutil.ReadFile(*resumeFileFlag)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's fine
			resumeState = make(map[string]bool)
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &resumeState)
}

// saveResumeState saves the current state of the scan
func saveResumeState(subdomain string, completed bool) error {
	if !*resumableFlag || *resumeFileFlag == "" {
		return nil
	}

	resumeState[subdomain] = completed

	data, err := json.Marshal(resumeState)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(*resumeFileFlag, data, 0644)
}

// checkRobotsTxt checks if scanning is allowed by robots.txt
func checkRobotsTxt(subdomain string) bool {
	if !*respectRobotsFlag {
		return true // Allowed if we don't respect robots.txt
	}

	// Check cache first
	if allowed, ok := robotsCache[subdomain]; ok {
		return allowed
	}

	scheme := "http"
	if *httpsFlag {
		scheme = "https"
	}

	robotsURL := fmt.Sprintf("%s://%s/robots.txt", scheme, subdomain)
	resp, err := httpClient.Get(robotsURL)
	if err != nil {
		// If we can't fetch robots.txt, assume allowed
		robotsCache[subdomain] = true
		return true
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// If robots.txt doesn't exist or can't be accessed, assume allowed
		robotsCache[subdomain] = true
		return true
	}

	// Very simple robots.txt parsing - just check for "Disallow: /"
	scanner := bufio.NewScanner(resp.Body)
	userAgentApplies := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Check if line is a user-agent line
		if strings.HasPrefix(line, "User-agent:") {
			agent := strings.TrimSpace(strings.TrimPrefix(line, "User-agent:"))
			if agent == "*" || strings.Contains(*userAgentFlag, agent) {
				userAgentApplies = true
			} else {
				userAgentApplies = false
			}
		}
		
		// Check if line is a disallow line that applies to us
		if userAgentApplies && strings.HasPrefix(line, "Disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			if path == "/" {
				// Disallowed
				robotsCache[subdomain] = false
				return false
			}
		}
	}

	// If we get here, assume allowed
	robotsCache[subdomain] = true
	return true
}

// takeScreenshot captures a screenshot of the subdomain
func takeScreenshot(subdomain string) (string, error) {
	if !*screenshotFlag {
		return "", nil
	}

	// Ensure screenshot directory exists
	if err := os.MkdirAll(*screenshotDirFlag, 0755); err != nil {
		return "", err
	}

	// Setup Chrome
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Add timeout
	ctx, cancel = context.WithTimeout(ctx, time.Duration(*timeoutFlag)*time.Second)
	defer cancel()

	scheme := "http"
	if *httpsFlag {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, subdomain)
	
	// Generate filename
	filename := filepath.Join(*screenshotDirFlag, fmt.Sprintf("%s_%d.png", 
		strings.ReplaceAll(subdomain, ".", "_"), time.Now().Unix()))

	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Wait for page to load
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return "", err
	}

	if err := ioutil.WriteFile(filename, buf, 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// sendNotification sends a notification about a vulnerable subdomain
func sendNotification(result Result) error {
	// Slack notification
	if *slackWebhookFlag != "" {
		message := slack.WebhookMessage{
			Text: fmt.Sprintf("*Subdomain Takeover Vulnerability Detected*\n"+
				"*Subdomain:* %s\n"+
				"*Service:* %s\n"+
				"*Risk Level:* %s\n"+
				"*CNAME:* %s\n",
				result.Subdomain, result.Service, result.RiskLevel, result.CNAME),
		}
		
		err := slack.PostWebhook(*slackWebhookFlag, &message)
		if err != nil {
			logger.Printf("Error sending Slack notification: %v", err)
		}
	}

	// Discord notification
	if *discordWebhookFlag != "" {
		// Implement Discord webhook notification
		// Similar to Slack but with Discord's webhook format
	}

	// Email notification
	if *emailFlag != "" && *smtpServerFlag != "" {
		// Implement email notification
	}

	return nil
}

// verifyTakeover attempts to verify if a subdomain is actually vulnerable to takeover
func verifyTakeover(result Result) (bool, string) {
	// This is a placeholder for the actual verification logic
	// In a real implementation, this would attempt to safely verify the takeover
	// without actually exploiting it
	
	// For now, we'll just return the existing result
	return result.TakeoverPossible, "Verification not implemented yet"
}

// DNSCache methods
func (c *DNSCache) Get(domain string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	cnames, ok := c.cache[domain]
	return cnames, ok
}

func (c *DNSCache) Set(domain string, cnames []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[domain] = cnames
}

// RateLimiter methods
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(r.lastUpdate).Seconds()
	r.bucket += elapsed * r.rate
	
	if r.bucket > r.rate {
		r.bucket = r.rate
	}
	
	if r.bucket < 1 {
		// Need to wait
		waitTime := (1 - r.bucket) / r.rate
		time.Sleep(time.Duration(waitTime * float64(time.Second)))
		r.bucket = 0
	} else {
		r.bucket -= 1
	}
	
	r.lastUpdate = time.Now()
}

func (r *RateLimiter) UpdateRate(responseTime time.Duration) {
	if !r.adaptive {
		return
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Simple adaptive algorithm: 
	// - If response time > 2s, reduce rate by 10%
	// - If response time < 0.5s, increase rate by 10%
	// - Keep rate between 1 and 100 req/s
	
	if responseTime > 2*time.Second {
		r.rate = math.Max(1, r.rate*0.9)
	} else if responseTime < 500*time.Millisecond {
		r.rate = math.Min(100, r.rate*1.1)
	}
}

// getServiceFromSubdomain performs a case-insensitive check of the provided string against our service_mapping.
func getServiceFromSubdomain(s string) string {
	// First, try direct match
	s = strings.ToLower(s)
	if service, ok := service_mapping[s]; ok {
		return service
	}

	// Try to match against each key in the service_mapping
	for cname, service := range service_mapping {
		if strings.Contains(s, cname) {
			return service
		}
	}

	// Try regex patterns from fingerprints
	for _, fp := range fingerprints {
		for _, pattern := range fp.Regex {
			if pattern == "" {
				continue
			}
			
			// Compile regex
			re, err := regexp.Compile(pattern)
			if err != nil {
				if *verboseFlag > 1 {
					logger.Printf("Invalid regex pattern: %s - %v", pattern, err)
				}
				continue
			}
			
			// Check if the pattern matches
			if re.MatchString(s) {
				return fp.Service
			}
		}
	}

	return ""
}

// detectServiceFromResponse tries to identify the service from HTTP response
func detectServiceFromResponse(resp *http.Response, body string) string {
	if resp == nil {
		return ""
	}
	
	// Check for fingerprints in headers
	for _, fp := range fingerprints {
		// Check headers
		headerMatch := true
		for headerName, headerValue := range fp.Headers {
			value := resp.Header.Get(headerName)
			if value == "" || !strings.Contains(strings.ToLower(value), strings.ToLower(headerValue)) {
				headerMatch = false
				break
			}
		}
		
		if headerMatch && len(fp.Headers) > 0 {
			return fp.Service
		}
		
		// Check response body
		for _, bodyPattern := range fp.Body {
			if strings.Contains(strings.ToLower(body), strings.ToLower(bodyPattern)) {
				return fp.Service
			}
		}
		
		// Check status codes
		for _, status := range fp.Status {
			if resp.StatusCode == status {
				// Status match alone is not enough, but combined with other indicators it helps
				if len(fp.Status) > 0 && (len(fp.Headers) > 0 || len(fp.Body) > 0) {
					return fp.Service
				}
			}
		}
	}
	
	// Run plugins if available
	for _, plugin := range plugins {
		if takeover, _, service := plugin.Execute(resp.Request.URL.Hostname(), nil); takeover {
			return service
		}
	}
	
	return ""
}

// printDetailedInfo displays a structured output for each subdomain.
func printDetailedInfo(subdomain, url string, resp *http.Response, cname, service string, takeover bool) {
	var statusCode int
	var headers map[string]string
	var riskLevel string
	
	if resp != nil {
		statusCode = resp.StatusCode
		headers = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
	}
	
	// Determine risk level based on service and takeover possibility
	if takeover {
		// Check if we have risk information from fingerprints
		for _, fp := range fingerprints {
			if fp.Service == service {
				riskLevel = fp.Risk
				break
			}
		}
		
		// Default to high risk if not specified
		if riskLevel == "" {
			riskLevel = "high"
		}
	} else {
		riskLevel = "none"
	}
	
	if takeover {
		// Vulnerable subdomain
		vulnColor := color.New(color.FgRed, color.Bold)
		vulnColor.Printf("[VULNERABLE] ")
		
		// Print risk level with appropriate color
		switch strings.ToLower(riskLevel) {
		case "high":
			color.New(color.FgRed).Printf("[HIGH RISK] ")
		case "medium":
			color.New(color.FgYellow).Printf("[MEDIUM RISK] ")
		case "low":
			color.New(color.FgCyan).Printf("[LOW RISK] ")
		default:
			color.New(color.FgRed).Printf("[RISK: %s] ", riskLevel)
		}
		
		fmt.Printf("%s\n", subdomain)
		fmt.Printf("  URL: %s\n", url)
		
		if statusCode > 0 {
			fmt.Printf("  Status: %d\n", statusCode)
		}
		
		if cname != "" {
			fmt.Printf("  CNAME: %s\n", cname)
		}
		
		if service != "" {
			fmt.Printf("  Service: %s\n", service)
		}
		
		// Print selected headers if verbose mode
		if *verboseFlag > 1 && len(headers) > 0 {
			fmt.Println("  Headers:")
			for k, v := range headers {
				fmt.Printf("    %s: %s\n", k, v)
			}
		}
		
		// Send notification for vulnerable subdomains
		result := Result{
			Subdomain:       subdomain,
			Status:          "vulnerable",
			StatusCode:      statusCode,
			CNAME:           cname,
			Service:         service,
			Headers:         headers,
			TakeoverPossible: takeover,
			RiskLevel:       riskLevel,
			Timestamp:       time.Now(),
		}
		
		// Take screenshot if enabled
		if *screenshotFlag {
			if screenshotPath, err := takeScreenshot(subdomain); err == nil {
				result.ScreenshotPath = screenshotPath
				fmt.Printf("  Screenshot: %s\n", screenshotPath)
			} else if *verboseFlag > 0 {
				logger.Printf("Error taking screenshot of %s: %v", subdomain, err)
			}
		}
		
		// Verify takeover if possible
		if verified, verificationMsg := verifyTakeover(result); verified {
			result.Verification = "verified"
			color.New(color.FgRed, color.Bold).Printf("  [VERIFIED] %s\n", verificationMsg)
		} else {
			result.Verification = "unverified"
		}
		
		// Send notification
		if err := sendNotification(result); err != nil && *verboseFlag > 0 {
			logger.Printf("Error sending notification: %v", err)
		}
		
		// Store in database if enabled
		if db != nil {
			// Implementation for database storage
		}
	} else if *deadRecord && cname != "" {
		// Dead record but valid CNAME
		color.Yellow("[DEAD RECORD] %s\n", subdomain)
		fmt.Printf("  URL: %s\n", url)
		
		if statusCode > 0 {
			fmt.Printf("  Status: %d\n", statusCode)
		}
		
		if cname != "" {
			fmt.Printf("  CNAME: %s\n", cname)
		}
		
		if service != "" {
			fmt.Printf("  Service: %s\n", service)
		}
	} else if !*hideFailed {
		// Not vulnerable
		if *cnameFlag && cname != "" {
			// Show CNAME info
			fmt.Printf("[NOT VULNERABLE] %s\n", subdomain)
			fmt.Printf("  URL: %s\n", url)
			
			if statusCode > 0 {
				fmt.Printf("  Status: %d\n", statusCode)
			}
			
			fmt.Printf("  CNAME: %s\n", cname)
			
			if service != "" {
				fmt.Printf("  Service: %s\n", service)
			}
		} else {
			// Simple output
			color.Green("[NOT VULNERABLE] %s\n", subdomain)
		}
	}
}

func checkSubdomain(subdomain string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Trace function execution time if verbose level is high enough
	defer traceTiming("checkSubdomain:" + subdomain)()
	
	debugPrint(2, "Processing subdomain: %s", subdomain)

	// Skip if already processed in a resumable scan
	if *resumableFlag {
		if completed, ok := resumeState[subdomain]; ok && completed {
			if *verboseFlag > 1 {
				logger.Printf("Skipping already processed subdomain: %s", subdomain)
			}
			return
		}
	}
	
	// Apply rate limiting if enabled
	if rateLimiter != nil {
		rateLimiter.Wait()
	}
	
	// Check robots.txt if respect-robots is enabled
	if !checkRobotsTxt(subdomain) {
		if *verboseFlag > 0 {
			logger.Printf("Skipping %s due to robots.txt disallow", subdomain)
		}
		return
	}

	// Start timing for adaptive rate limiting
	startTime := time.Now()

	// Check for CNAME records
	var cnames []string
	var err error
	
	// Check DNS cache first
	if dnsCache != nil {
		if cachedCnames, found := dnsCache.Get(subdomain); found {
			cnames = cachedCnames
			debugPrint(2, "DNS cache hit for %s: %v", subdomain, cnames)
			if debugStats != nil {
				debugStats.IncrementCacheHits()
			}
		} else {
			debugPrint(3, "DNS cache miss for %s", subdomain)
		}
	}
	
	// If not in cache, perform DNS lookup
	if len(cnames) == 0 {
		if *dohFlag != "" {
			// Use DNS over HTTPS
			// Implementation for DoH would go here
		} else if *dnsServerFlag != "" {
			// Use custom DNS server
			r := &dns.Msg{}
			r.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)
			
			c := &dns.Client{}
			in, _, err := c.Exchange(r, *dnsServerFlag)
			if err == nil && in != nil && len(in.Answer) > 0 {
				for _, ans := range in.Answer {
					if cname, ok := ans.(*dns.CNAME); ok {
						cnames = append(cnames, cname.Target)
					}
				}
			}
		} else {
			// Use standard DNS lookup
			cnames, err = net.LookupCNAME(subdomain)
			if err == nil && cnames != "" {
				cnames = []string{cnames}
			} else {
				cnames = []string{}
			}
		}
		
		// Store in cache
		if dnsCache != nil && len(cnames) > 0 {
			dnsCache.Set(subdomain, cnames)
		}
	}

	// Determine if we should send HTTP requests
	shouldRequest := *allRequests || len(cnames) > 0

	if !shouldRequest {
		if !*hideFailed && !*errorFlag {
			if *verboseFlag > 0 {
				logger.Printf("No CNAME record found for %s", subdomain)
			}
		}
		
		// Mark as completed in resume state
		if *resumableFlag {
			saveResumeState(subdomain, true)
		}
		
		results <- Result{
			Subdomain:       subdomain,
			Status:          "no_cname",
			Timestamp:       time.Now(),
			TakeoverPossible: false,
		}
		return
	}

	// Determine if any of the CNAMEs match known services
	var service string
	var matchedCNAME string
	
	for _, cname := range cnames {
		service = getServiceFromSubdomain(cname)
		if service != "" {
			matchedCNAME = cname
			break
		}
	}

	// Prepare HTTP request
	scheme := "http"
	if *httpsFlag {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, subdomain)

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		if !*errorFlag {
			if *verboseFlag > 0 {
				logger.Printf("Error creating request for %s: %v", subdomain, err)
			}
		}
		
		// Mark as completed in resume state
		if *resumableFlag {
			saveResumeState(subdomain, true)
		}
		
		results <- Result{
			Subdomain:       subdomain,
			Status:          "error",
			CNAME:           matchedCNAME,
			Service:         service,
			ErrorMessage:    err.Error(),
			Timestamp:       time.Now(),
			TakeoverPossible: false,
		}
		return
	}

	// Set custom User-Agent
	req.Header.Set("User-Agent", *userAgentFlag)
	debugPrint(3, "Sending HTTP request to %s with User-Agent: %s", url, *userAgentFlag)
	
	// Track request in stats
	if debugStats != nil {
		debugStats.IncrementRequests()
	}
	
	// Measure response time
	requestStart := time.Now()
	resp, err := client.Do(req)
	requestDuration := time.Since(requestStart)
	
	// Record response time in stats
	if debugStats != nil {
		debugStats.AddResponseTime(requestDuration)
	}
	
	debugPrint(2, "HTTP request to %s completed in %v", url, requestDuration)
	
	// Update rate limiter with response time
	if rateLimiter != nil && rateLimiter.adaptive {
		rateLimiter.UpdateRate(time.Since(startTime))
	}
	
	if err != nil {
		// Check if this is a potential takeover
		isTakeover := false
		if matchedCNAME != "" && service != "" {
			isTakeover = true
		}

		if !*errorFlag || isTakeover {
			if isTakeover {
				printDetailedInfo(subdomain, url, nil, matchedCNAME, service, true)
				
				// Mark as completed in resume state
				if *resumableFlag {
					saveResumeState(subdomain, true)
				}
				
				results <- Result{
					Subdomain:       subdomain,
					Status:          "vulnerable",
					CNAME:           matchedCNAME,
					Service:         service,
					ErrorMessage:    err.Error(),
					TakeoverPossible: true,
					RiskLevel:       "high", // Default to high for connection errors with known services
					Timestamp:       time.Now(),
				}
			} else if !*errorFlag {
				if *verboseFlag > 0 {
					logger.Printf("Error connecting to %s: %v", url, err)
				}
				
				// Mark as completed in resume state
				if *resumableFlag {
					saveResumeState(subdomain, true)
				}
				
				results <- Result{
					Subdomain:       subdomain,
					Status:          "error",
					CNAME:           matchedCNAME,
					Service:         service,
					ErrorMessage:    err.Error(),
					Timestamp:       time.Now(),
					TakeoverPossible: false,
				}
			}
		}
		return
	}
	defer resp.Body.Close()

	// Read response body for content-based fingerprinting
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	
	// Try to detect service from response if not already identified
	if service == "" {
		service = detectServiceFromResponse(resp, bodyStr)
	}

	// Check for takeover indicators in the response
	isTakeover := false
	
	// Check status code (common takeover indicator is 404)
	if resp.StatusCode == 404 || resp.StatusCode == 403 {
		// Check if we have a known service
		if service != "" {
			isTakeover = true
			debugPrint(1, "Potential takeover detected for %s (status: %d, service: %s)", subdomain, resp.StatusCode, service)
		}
	}
	
	debugPrint(3, "Response status code: %d, service: %s, CNAME: %s", resp.StatusCode, service, matchedCNAME)
	
	// Check for specific content patterns that indicate takeover
	for _, fp := range fingerprints {
		if fp.Service == service {
			// Check body patterns
			for _, pattern := range fp.Body {
				if strings.Contains(bodyStr, pattern) {
					isTakeover = true
					break
				}
			}
		}
	}

	// Print detailed information
	printDetailedInfo(subdomain, url, resp, matchedCNAME, service, isTakeover)
	
	// Update statistics
	if debugStats != nil {
		debugStats.IncrementProcessed()
		if isTakeover {
			debugStats.IncrementVulnerable()
		}
	}
	
	// Mark as completed in resume state
	if *resumableFlag {
		saveResumeState(subdomain, true)
	}
	
	debugPrint(2, "Completed processing subdomain: %s", subdomain)
	
	// Create result
	result := Result{
		Subdomain:       subdomain,
		Status:          fmt.Sprintf("%d", resp.StatusCode),
		StatusCode:      resp.StatusCode,
		CNAME:           matchedCNAME,
		Service:         service,
		TakeoverPossible: isTakeover,
		Timestamp:       time.Now(),
	}
	
	// Add response body if verbose
	if *verboseFlag > 2 {
		// Truncate body to avoid excessive memory usage
		if len(bodyStr) > 1000 {
			result.ResponseBody = bodyStr[:1000] + "... [truncated]"
		} else {
			result.ResponseBody = bodyStr
		}
	}
	
	// Add headers if verbose
	if *verboseFlag > 1 {
		result.Headers = make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.Headers[k] = v[0]
			}
		}
	}
	
	results <- result
}

func main() {
	// Print banner
	fmt.Printf(BANNER, VERSION)
	
	// Parse command-line flags
	flag.Parse()
	
	// Initialize logger
	initLogger()
	
	// Log startup information
	logger.Printf("SubX v%s - Subdomain Takeover Scanner", VERSION)
	
	// Handle update and upgrade flags first
	if *updateFlag || *upgradeFlag {
		latestVersion, hasUpdate, err := checkForUpdates()
		if err != nil {
			logger.Fatalf("Error checking for updates: %v", err)
		}
		
		if hasUpdate {
			fmt.Printf("A new version of SubX is available: %s (current: %s)\n", latestVersion, VERSION)
			
			if *upgradeFlag {
				// Perform the upgrade
				if err := upgradeSubX(); err != nil {
					logger.Fatalf("Error upgrading SubX: %v", err)
				}
				// Exit after upgrade
				os.Exit(0)
			}
		} else {
			fmt.Printf("SubX is up to date (version %s)\n", VERSION)
		}
		
		// If only checking for updates, exit after reporting
		if *updateFlag && !*upgradeFlag {
			os.Exit(0)
		}
	}
	
	// Load configuration file if specified
	if *configFlag != "" {
		if err := loadConfig(*configFlag); err != nil {
			logger.Fatalf("Error loading configuration: %v", err)
		}
		applyConfig()
	}
	
	// Initialize components
	initHTTPClient()
	initDNSCache()
	initRateLimiter()
	
	// Initialize robots.txt cache
	robotsCache = make(map[string]bool)
	
	// Initialize database if needed
	if *dbPathFlag != "" {
		if err := initDatabase(); err != nil {
			logger.Printf("Error initializing database: %v", err)
		}
	}
	
	// Load plugins
	if *pluginDirFlag != "" {
		if err := loadPlugins(); err != nil {
			logger.Printf("Error loading plugins: %v", err)
		}
	}
	
	// Load resume state if resumable scanning is enabled
	if *resumableFlag {
		if err := loadResumeState(); err != nil {
			logger.Printf("Error loading resume state: %v", err)
		}
	}

	// Load external service fingerprints from the provided JSON URL.
	loadExternalServices("https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json")

	// Start API server if requested
	if *apiFlag {
		go startAPIServer()
	}
	
	// Start web UI if requested
	if *webUIFlag {
		go startWebUI()
	}
	
	// Start distributed scanning if requested
	if *distributedFlag {
		if *workerFlag {
			// Run as worker
			startWorkerNode()
			return
		} else if *masterFlag != "" {
			// Connect to master
			// Implementation for distributed scanning
		}
	}

	var subdomains []string
	if *urlFlag != "" {
		subdomains = append(subdomains, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			logger.Fatalf("Error opening file: %v", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomains = append(subdomains, strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			logger.Fatalf("Error reading file: %v", err)
			return
		}
	} else {
		logger.Fatalf("No input provided. Use -u for a single domain or -l for a list of domains.")
		return
	}
	
	// Initialize debug statistics
	debugStats = NewScanStats(len(subdomains))
	debugPrint(1, "Starting scan with %d subdomains", len(subdomains))
	
	// Initialize progress bar if not in interactive mode
	if !*interactiveFlag && *verboseFlag > 0 {
		progressBar = progressbar.NewOptions(len(subdomains),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(50),
			progressbar.OptionSetDescription("Scanning subdomains..."),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
		debugPrint(1, "Progress bar initialized")
	}

	results := make(chan Result, len(subdomains))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *threadsFlag)
	
	// Start scan timestamp for database
	scanStartTime := time.Now()
	var scanID int64 = 0
	
	// Create scan record in database if enabled
	if db != nil {
		result, err := db.Exec("INSERT INTO scans (timestamp, description) VALUES (?, ?)",
			scanStartTime, fmt.Sprintf("Scan of %d subdomains", len(subdomains)))
		if err != nil {
			logger.Printf("Error creating scan record: %v", err)
		} else {
			scanID, _ = result.LastInsertId()
		}
	}

	// Start interactive mode if enabled
	if *interactiveFlag {
		go startInteractiveMode(subdomains, results)
	} else {
		// Normal scanning mode
		for _, subdomain := range subdomains {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(sd string) {
				defer func() { <-semaphore }()
				checkSubdomain(sd, results, &wg)
				if progressBar != nil {
					progressBar.Add(1)
				}
			}(subdomain)
		}
	}

	go func() {
		wg.Wait()
		close(results)
		if progressBar != nil {
			progressBar.Finish()
		}
	}()

	// Process results
	var allResults []Result
	
	// Output results to a file if specified; otherwise, results are printed to the console.
	outputFile := *outputFlag
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			logger.Fatalf("Error creating output file: %v", err)
			return
		}
		defer file.Close()

		if strings.HasSuffix(outputFile, ".json") {
			// JSON output
			jsonEncoder := json.NewEncoder(file)
			jsonEncoder.SetIndent("", "  ")
			file.WriteString("[")
			first := true
			for res := range results {
				if !first {
					file.WriteString(",\n")
				}
				jsonEncoder.Encode(res)
				first = false
				allResults = append(allResults, res)
				
				// Store in database if enabled
				if db != nil && scanID > 0 {
					storeResultInDatabase(scanID, res)
				}
			}
			file.WriteString("\n]")
		} else if strings.HasSuffix(outputFile, ".html") {
			// HTML output
			// Collect all results first
			for res := range results {
				allResults = append(allResults, res)
				
				// Store in database if enabled
				if db != nil && scanID > 0 {
					storeResultInDatabase(scanID, res)
				}
			}
			
			// Generate HTML report
			generateHTMLReport(file, allResults)
		} else if strings.HasSuffix(outputFile, ".csv") {
			// CSV output
			file.WriteString("Subdomain,Status,StatusCode,CNAME,Service,TakeoverPossible,RiskLevel,Timestamp\n")
			for res := range results {
				file.WriteString(fmt.Sprintf("%s,%s,%d,%s,%s,%t,%s,%s\n",
					res.Subdomain, res.Status, res.StatusCode, res.CNAME, res.Service,
					res.TakeoverPossible, res.RiskLevel, res.Timestamp.Format(time.RFC3339)))
				allResults = append(allResults, res)
				
				// Store in database if enabled
				if db != nil && scanID > 0 {
					storeResultInDatabase(scanID, res)
				}
			}
		} else {
			// Plain text output
			for res := range results {
				if res.TakeoverPossible {
					file.WriteString(fmt.Sprintf("[VULNERABLE] %s - %s - %s\n", res.Subdomain, res.Service, res.CNAME))
				} else if !*hideFailed {
					file.WriteString(fmt.Sprintf("%s - %s\n", res.Subdomain, res.Status))
				}
				allResults = append(allResults, res)
				
				// Store in database if enabled
				if db != nil && scanID > 0 {
					storeResultInDatabase(scanID, res)
				}
			}
		}
	} else {
		// Just collect results for statistics
		for res := range results {
			allResults = append(allResults, res)
			
			// Store in database if enabled
			if db != nil && scanID > 0 {
				storeResultInDatabase(scanID, res)
			}
		}
	}
	
	// Print summary
	printSummary(allResults)
}

// startAPIServer starts the RESTful API server
func startAPIServer() {
	router := mux.NewRouter()
	
	// Define API endpoints
	router.HandleFunc("/api/scan", handleScanRequest).Methods("POST")
	router.HandleFunc("/api/results", handleGetResults).Methods("GET")
	router.HandleFunc("/api/status", handleGetStatus).Methods("GET")
	
	// Start server
	logger.Printf("Starting API server on port %d", *apiPortFlag)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *apiPortFlag), router); err != nil {
		logger.Printf("API server error: %v", err)
	}
}

// startWebUI starts the web user interface
func startWebUI() {
	router := mux.NewRouter()
	
	// Define web UI routes
	router.HandleFunc("/", handleWebUIHome)
	router.HandleFunc("/scan", handleWebUIScan).Methods("POST")
	router.HandleFunc("/results", handleWebUIResults)
	
	// Serve static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	
	// Start server
	logger.Printf("Starting Web UI on port %d", *webPortFlag)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *webPortFlag), router); err != nil {
		logger.Printf("Web UI server error: %v", err)
	}
}

// startWorkerNode starts a worker node for distributed scanning
func startWorkerNode() {
	logger.Printf("Starting worker node on port %d", *workerPortFlag)
	
	// Implementation for worker node
}

// startInteractiveMode starts the interactive CLI mode
func startInteractiveMode(subdomains []string, results chan<- Result) {
	// Implementation for interactive mode
}

// checkForUpdates checks if a newer version of SubX is available
func checkForUpdates() (string, bool, error) {
	logger.Printf("Checking for updates from %s...", *updateURLFlag)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *sslFlag},
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	
	// Set up request with custom user agent
	req, err := http.NewRequest("GET", *updateURLFlag, nil)
	if err != nil {
		return "", false, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("User-Agent", *userAgentFlag)
	
	// Make request to GitHub API
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("error checking for updates: %v", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("received non-OK response: %s", resp.Status)
	}
	
	// Parse response
	var release struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		PublishedAt string `json:"published_at"`
		Body        string `json:"body"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", false, fmt.Errorf("error parsing response: %v", err)
	}
	
	// Extract version number from tag name (remove 'v' prefix if present)
	latestVersion := release.TagName
	if len(latestVersion) > 0 && latestVersion[0] == 'v' {
		latestVersion = latestVersion[1:]
	}
	
	// Compare versions
	currentVersion := VERSION
	hasUpdate := compareVersions(currentVersion, latestVersion) < 0 || *forceUpdateFlag
	
	return latestVersion, hasUpdate, nil
}

// compareVersions compares two semantic version strings
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Split versions into components
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	// Compare each component
	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		// Parse component to integer
		num1, err1 := strconv.Atoi(parts1[i])
		num2, err2 := strconv.Atoi(parts2[i])
		
		// Handle parsing errors
		if err1 != nil || err2 != nil {
			// Fall back to string comparison if parsing fails
			if parts1[i] < parts2[i] {
				return -1
			} else if parts1[i] > parts2[i] {
				return 1
			}
			continue
		}
		
		// Compare numeric values
		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}
	
	// If all components so far are equal, the longer version is considered greater
	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	
	// Versions are equal
	return 0
}

// upgradeSubX downloads and installs the latest version of SubX
func upgradeSubX() error {
	// Get the latest version information
	latestVersion, hasUpdate, err := checkForUpdates()
	if err != nil {
		return fmt.Errorf("error checking for updates: %v", err)
	}
	
	// Check if update is needed
	if !hasUpdate && !*forceUpdateFlag {
		fmt.Printf("SubX is already at the latest version (%s).\n", VERSION)
		return nil
	}
	
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error getting executable path: %v", err)
	}
	
	// Create a backup of the current executable
	backupPath := execPath + ".backup"
	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("error creating backup: %v", err)
	}
	
	fmt.Printf("Upgrading SubX from %s to %s...\n", VERSION, latestVersion)
	
	// Determine platform and architecture
	var platform string
	var arch string
	
	switch runtime.GOOS {
	case "windows":
		platform = "windows"
	case "darwin":
		platform = "macos"
	case "linux":
		platform = "linux"
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64"
	case "386":
		arch = "386"
	case "arm64":
		arch = "arm64"
	case "arm":
		arch = "arm"
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	
	// Construct download URL
	downloadURL := fmt.Sprintf("https://github.com/Karthikdude/SubX/releases/download/v%s/subx_%s_%s", latestVersion, platform, arch)
	if platform == "windows" {
		downloadURL += ".exe"
	}
	
	// Download the new version
	fmt.Printf("Downloading from %s...\n", downloadURL)
	
	client := &http.Client{
		Timeout: time.Minute * 5, // Longer timeout for download
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *sslFlag},
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("error creating download request: %v", err)
	}
	req.Header.Set("User-Agent", *userAgentFlag)
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error downloading update: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response when downloading: %s", resp.Status)
	}
	
	// Create temporary file for download
	tempFile, err := os.CreateTemp("", "subx-update-*")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // Clean up temp file on exit
	
	// Copy download to temporary file
	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		tempFile.Close()
		return fmt.Errorf("error saving download: %v", err)
	}
	tempFile.Close()
	
	// Make temporary file executable (Unix only)
	if platform != "windows" {
		if err := os.Chmod(tempPath, 0755); err != nil {
			return fmt.Errorf("error setting executable permissions: %v", err)
		}
	}
	
	// Replace current executable with the new version
	if err := replaceFile(tempPath, execPath); err != nil {
		// Try to restore backup on failure
		replaceFile(backupPath, execPath)
		return fmt.Errorf("error installing update: %v\nRestored backup.", err)
	}
	
	fmt.Printf("Successfully upgraded SubX to version %s!\n", latestVersion)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	
	_, err = io.Copy(dstFile, srcFile)
	return err
}

// replaceFile replaces the target file with the source file
func replaceFile(src, dst string) error {
	// On Windows, we need to rename the destination file first
	if runtime.GOOS == "windows" {
		// Remove the destination file if it exists
		os.Remove(dst)
	}
	
	// Move the source file to the destination
	return os.Rename(src, dst)
}

// generateHTMLReport generates an HTML report from the results
func generateHTMLReport(w io.Writer, results []Result) {
	// HTML template for the report
	const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubX Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .vulnerable {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
            padding: 10px;
            margin-bottom: 10px;
        }
        .not-vulnerable {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
            padding: 10px;
            margin-bottom: 10px;
        }
        .error {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
            padding: 10px;
            margin-bottom: 10px;
        }
        .high-risk { color: #d32f2f; font-weight: bold; }
        .medium-risk { color: #f57c00; font-weight: bold; }
        .low-risk { color: #0288d1; font-weight: bold; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .screenshot {
            max-width: 300px;
            border: 1px solid #ddd;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <h1>SubX Subdomain Takeover Scan Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Scan completed at: {{.Timestamp}}</p>
        <p>Total subdomains scanned: {{.Total}}</p>
        <p>Vulnerable subdomains: <span class="high-risk">{{.Vulnerable}}</span></p>
        <p>High risk: <span class="high-risk">{{.HighRisk}}</span></p>
        <p>Medium risk: <span class="medium-risk">{{.MediumRisk}}</span></p>
        <p>Low risk: <span class="low-risk">{{.LowRisk}}</span></p>
    </div>
    
    {{if .VulnerableResults}}
    <h2>Vulnerable Subdomains</h2>
    {{range .VulnerableResults}}
    <div class="vulnerable">
        <h3>{{.Subdomain}}</h3>
        <p><strong>Service:</strong> {{.Service}}</p>
        <p><strong>CNAME:</strong> {{.CNAME}}</p>
        <p><strong>Risk Level:</strong> 
            {{if eq .RiskLevel "high"}}<span class="high-risk">High</span>{{end}}
            {{if eq .RiskLevel "medium"}}<span class="medium-risk">Medium</span>{{end}}
            {{if eq .RiskLevel "low"}}<span class="low-risk">Low</span>{{end}}
        </p>
        <p><strong>Status:</strong> {{.Status}}</p>
        {{if .ScreenshotPath}}
        <p><strong>Screenshot:</strong></p>
        <img src="{{.ScreenshotPath}}" alt="Screenshot of {{.Subdomain}}" class="screenshot">
        {{end}}
    </div>
    {{end}}
    {{end}}
    
    <h2>All Results</h2>
    <table>
        <tr>
            <th>Subdomain</th>
            <th>Status</th>
            <th>CNAME</th>
            <th>Service</th>
            <th>Takeover Possible</th>
            <th>Risk Level</th>
        </tr>
        {{range .AllResults}}
        <tr>
            <td>{{.Subdomain}}</td>
            <td>{{.Status}}</td>
            <td>{{.CNAME}}</td>
            <td>{{.Service}}</td>
            <td>{{.TakeoverPossible}}</td>
            <td>
                {{if eq .RiskLevel "high"}}<span class="high-risk">High</span>{{end}}
                {{if eq .RiskLevel "medium"}}<span class="medium-risk">Medium</span>{{end}}
                {{if eq .RiskLevel "low"}}<span class="low-risk">Low</span>{{end}}
                {{if eq .RiskLevel "none"}}None{{end}}
            </td>
        </tr>
        {{end}}
    </table>
    
    <footer>
        <p>Generated by SubX v{{.Version}} at {{.Timestamp}}</p>
    </footer>
</body>
</html>
`

	// Count statistics
	var vulnerable, highRisk, mediumRisk, lowRisk int
	var vulnerableResults []Result
	
	for _, res := range results {
		if res.TakeoverPossible {
			vulnerable++
			vulnerableResults = append(vulnerableResults, res)
			
			switch strings.ToLower(res.RiskLevel) {
			case "high":
				highRisk++
			case "medium":
				mediumRisk++
			case "low":
				lowRisk++
			}
		}
	}
	
	// Prepare template data
	data := struct {
		Timestamp         string
		Total             int
		Vulnerable        int
		HighRisk          int
		MediumRisk        int
		LowRisk           int
		VulnerableResults []Result
		AllResults        []Result
		Version           string
	}{
		Timestamp:         time.Now().Format(time.RFC1123),
		Total:             len(results),
		Vulnerable:        vulnerable,
		HighRisk:          highRisk,
		MediumRisk:        mediumRisk,
		LowRisk:           lowRisk,
		VulnerableResults: vulnerableResults,
		AllResults:        results,
		Version:           VERSION,
	}
	
	// Execute template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		logger.Printf("Error creating HTML template: %v", err)
		return
	}
	
	if err := tmpl.Execute(w, data); err != nil {
		logger.Printf("Error generating HTML report: %v", err)
	}
}

// storeResultInDatabase stores a scan result in the database
func storeResultInDatabase(scanID int64, result Result) {
	if db == nil {
		return
	}
	
	_, err := db.Exec(`
		INSERT INTO results (
			scan_id, subdomain, status, status_code, cname, service, 
			takeover_possible, risk_level, verification, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		scanID, result.Subdomain, result.Status, result.StatusCode, result.CNAME, result.Service,
		result.TakeoverPossible, result.RiskLevel, result.Verification, result.Timestamp,
	)
	
	if err != nil && *verboseFlag > 0 {
		logger.Printf("Error storing result in database: %v", err)
	}
}

// printSummary prints a summary of the scan results
func printSummary(results []Result) {
	var total, vulnerable, errors int
	
	for _, res := range results {
		total++
		if res.TakeoverPossible {
			vulnerable++
		}
		if res.Status == "error" {
			errors++
		}
	}
	
	// Mark scan as finished in debug stats
	if debugStats != nil {
		debugStats.Finish()
	}
	
	fmt.Println("\n--- Scan Summary ---")
	fmt.Printf("Total subdomains scanned: %d\n", total)
	fmt.Printf("Vulnerable subdomains: %d\n", vulnerable)
	fmt.Printf("Errors encountered: %d\n", errors)
	fmt.Printf("Scan completed at: %s\n", time.Now().Format(time.RFC1123))
	
	// Print detailed statistics if available
	if debugStats != nil {
		stats := debugStats.GetStats()
		
		fmt.Println("\n--- Detailed Statistics ---")
		fmt.Printf("Scan duration: %.2f seconds\n", stats["duration_seconds"])
		fmt.Printf("Processing rate: %.2f domains/second\n", stats["domains_per_second"])
		fmt.Printf("Total HTTP requests: %d\n", stats["total_requests"])
		fmt.Printf("DNS cache hits: %d\n", stats["cache_hits"])
		fmt.Printf("Average response time: %d ms\n", stats["average_response_ms"])
		
		// Log detailed statistics
		debugPrint(1, "Scan completed in %.2f seconds", stats["duration_seconds"])
		debugPrint(1, "Processed %d domains at %.2f domains/second", stats["processed_domains"], stats["domains_per_second"])
		debugPrint(1, "Found %d vulnerable domains", stats["vulnerable_domains"])
		debugPrint(1, "Made %d HTTP requests with %d DNS cache hits", stats["total_requests"], stats["cache_hits"])
		debugPrint(1, "Average response time: %d ms", stats["average_response_ms"])
	}
}

// API and Web UI handler functions
func handleScanRequest(w http.ResponseWriter, r *http.Request) {
	// Implementation for API scan endpoint
}

func handleGetResults(w http.ResponseWriter, r *http.Request) {
	// Implementation for API results endpoint
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	// Implementation for API status endpoint
}

func handleWebUIHome(w http.ResponseWriter, r *http.Request) {
	// Implementation for web UI home page
}

func handleWebUIScan(w http.ResponseWriter, r *http.Request) {
	// Implementation for web UI scan page
}

func handleWebUIResults(w http.ResponseWriter, r *http.Request) {
	// Implementation for web UI results page
}
