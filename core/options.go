package core

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var verbose bool

func EnableVerbose() {
	verbose = true
}

func VerboseEnabled() bool {
	return verbose
}

func LogVerbose(format string, args ...any) {
	if !verbose {
		return
	}
	log.Printf(format, args...)
}

type Options struct {
	RawURL          string
	URL             url.URL
	TargetsFile     string
	Target          Target
	Port            int
	Path2Sitemap    string
	Workers         int
	ProxyAddr       string
	Pprof           bool
	NeedRunKatana   bool
	TLSProfile      string
	MaxRetries      int
	Tech            string
	Timeout         time.Duration
	Delay           time.Duration
	RateLimit       int
	RateLimitPerMin int
	RateIntervalStr string
	RateInterval    time.Duration
	ExitOnFind      bool
	ExtraHeaders    HeaderMap
	Quiet           bool
	Verbose         bool
	OutputFile      string
	TelegramChatID  string
	TelegramReport  bool
	Theory          bool
}

func ParseOptions() Options {
	var opts Options

	flag.Usage = printUsage

	help := flag.Bool("help", false, "Show this help")

	flag.StringVar(&opts.RawURL, "u", "", "Target URL, e.g. https://host:port/path")
	flag.IntVar(&opts.Port, "p", 0, "Target port (optional, overrides URL:port)")
	flag.StringVar(&opts.Path2Sitemap, "s", "", "Apply sitemap for certain modules (jsonl format)")
	flag.StringVar(&opts.ProxyAddr, "proxy", "", "Proxy address (host:port)")
	flag.StringVar(&opts.TargetsFile, "f", "", "JSON file with list of targets (url, header,sitemap, output file)")
	flag.BoolVar(&opts.Pprof, "pprof", false, "Pprof server (debug purposes)")
	flag.IntVar(&opts.Workers, "w", 4, "Number of parallel request smugglingers (for list of tarhets)")
	flag.StringVar(&opts.TLSProfile, "tls", "default", "TLS impersonation: default|chrome|firefox|safari|edge|random|random-strict")
	flag.BoolVar(&opts.NeedRunKatana, "rk", false, "Autorun katana w predefined flags (prior over '-s sitemap.jsonl' oprion)")
	flag.BoolVar(&opts.NeedRunKatana, "run-katana", false, "Autorun katana w predefined flags (prior over '-s sitemap.jsonl' oprion)")

	flag.StringVar(&opts.Tech, "tech", "all", "Techniques to run (e.g. h1,h2,clte,tecl,tete,h2te,h2cl,h2crlf,all)")
	flag.Var(&opts.ExtraHeaders, "H", "Custom header (Can be used multiple times)")
	flag.BoolVar(&opts.ExitOnFind, "x", false, "Exit scan after first finding")
	flag.IntVar(&opts.MaxRetries, "r", 3, "Max retries per module")
	flag.DurationVar(&opts.Timeout, "t", 10*time.Second, "Request timeout")
	flag.DurationVar(&opts.Delay, "delay", 5*time.Second, "Delay between running modules")
	flag.IntVar(&opts.RateLimit, "rl", 5, "Requests per second rate limit")
	flag.IntVar(&opts.RateLimitPerMin, "rpm", 0, "Requests per minute rate limit (0 = disabled)")
	flag.StringVar(&opts.RateIntervalStr, "ri", "", "Explicit delay between requests (eg 5s or 10m)")

	flag.BoolVar(&opts.TelegramReport, "tg-report", false, "Send report to Telegram")
	flag.StringVar(&opts.TelegramChatID, "tg-chat", "", "Telegram chat ID")
	flag.BoolVar(&opts.Verbose, "v", false, "Verbose mode (debug logs)")
	flag.StringVar(&opts.OutputFile, "o", "smuggler.log", "Output log file")
	flag.BoolVar(&opts.Quiet, "q", false, "Quiet mode (no banner, minimal output)")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Quiet mode (no banner, minimal output)")
	flag.BoolVar(&opts.Theory, "theory", false, "Show theoretical materials 'bout request smuggling")

	flag.Parse()

	if *help {
		showBanner()
		flag.Usage()
		os.Exit(0)
	}

	if !opts.Quiet {
		showBanner()
	}

	opts.TLSProfile = strings.ToLower(strings.TrimSpace(opts.TLSProfile))
	switch opts.TLSProfile {
	case "", "default":
		opts.TLSProfile = "default"
	case "chrome", "firefox", "safari", "edge", "random", "random-strict":

	default:
		log.Fatalf("unknown -tls profile %q (supported: default, chrome, firefox, safari, edge, random, random-strict)", opts.TLSProfile)
	}

	if opts.TargetsFile == "" && opts.RawURL == "" && !opts.Theory {
		log.Fatal("use -u to specify target URL, e.g. -u https://example.com/ or -f to use targets file")
	}

	if opts.RawURL != "" {
		if err := InitTargetFromOptions(&opts); err != nil {
			log.Fatal(err)
		}
	}

	if err := calculateRateInterval(&opts); err != nil {
		log.Fatalf("Rate limit config error: %v\n", err)
	}
	return opts
}

type TLSFactory interface {
	H1Transport(opts Options) *http.Transport
	H2Dialer(opts Options) (net.Conn, error)
}

func calculateRateInterval(opts *Options) error {

	if opts.RateIntervalStr != "" {
		dur, err := time.ParseDuration(opts.RateIntervalStr)
		if err != nil {
			return fmt.Errorf("invalid RateIntervalStr %q: %w", opts.RateIntervalStr, err)
		}
		opts.RateInterval = dur
		return nil
	}

	if opts.RateLimitPerMin > 0 {
		opts.RateInterval = time.Minute / time.Duration(opts.RateLimitPerMin)
		return nil
	}

	if opts.RateLimit > 0 {
		opts.RateInterval = time.Second / time.Duration(opts.RateLimit)
		return nil
	}

	opts.RateInterval = 400 * time.Millisecond
	return nil
}

func InitTargetFromOptions(opts *Options) error {
	if opts.RawURL == "" {
		return fmt.Errorf("RawURL is empty")
	}

	parsed, err := url.Parse(opts.RawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", opts.RawURL, err)
	}

	host := parsed.Hostname()
	portStr := parsed.Port()
	pathStr := parsed.Path
	tls := false
	port := 0

	switch parsed.Scheme {
	case "https":
		tls = true
		if portStr == "" {
			port = 443
		}
	case "http", "":
		tls = false
		if portStr == "" {
			port = 80
		}
	default:
		return fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}

	if opts.Port != 0 {
		port = opts.Port
	}

	if pathStr == "" {
		pathStr = "/"
	}

	endpoint := fmt.Sprintf("%s:%d", host, port)

	var sitemap []Record

	if opts.NeedRunKatana {

		fileName, err := runKatana(opts.RawURL, "1")
		if err != nil {
			log.Printf("Warning: failed to run katana, fallback to '-s sitemap.jsonl option': %v", err)
		} else {
			opts.Path2Sitemap = fileName
		}
	}

	if opts.Path2Sitemap != "" {
		sm, err := createSitemap(opts.Path2Sitemap)
		if err != nil {
			log.Printf("Warning: failed to load sitemap: %v", err)
			sitemap = fallbackSitemap(opts.RawURL)
		} else if len(sm) == 0 {
			log.Println("Warning: sitemap is empty, using default endpoint")
			sitemap = fallbackSitemap(opts.RawURL)
		} else {
			sitemap = sm
		}
	} else {

		sitemap = fallbackSitemap(opts.RawURL)
	}

	target := Target{
		Host:         host,
		Port:         port,
		TLS:          tls,
		Path:         pathStr,
		Endpoint:     endpoint,
		ExtraHeaders: http.Header(opts.ExtraHeaders),
		Sitemap:      sitemap,
	}

	opts.Target = target

	return nil
}

func showBanner() {
	fmt.Println(`                              /._      ,
                             /     \   / \
                             ) ,-==-> /\/ \
                              )__\\/ // \  |
                             /  /' \//   | |
                            /  (  /|/    | /
                           /     //|    /,'
                          // /  (( )    '
                         //     // \    |
                        //     (#) |
                       /        )\/ \   '       ____
                      /        /#/   )         /,.__\__,,--=_,
                     /         \#\  /)      __/ + \n00b,--==<
                     //ubica___/#/_/'      (\_\__+/_,   ---<^
                                                    '==--=='`)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "ubican00b0v – HTTP/1.1 & HTTP/2 desync scanner\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n  ubican00b0v -u URL [options]\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  -u        string        Target URL (https://host:port/path)\n")
	fmt.Fprintf(os.Stderr, "  -f        string        JSON file containing targets (add_target.sh helps)\n")
	fmt.Fprintf(os.Stderr, "  -p        int           Target port (overrides URL port)\n")
	fmt.Fprintf(os.Stderr, "  -tech     string        Techniques (h1,h2,clte,tecl,h2te...)\n\n")
	fmt.Fprintf(os.Stderr, "  -rk -run-katana     bool        Autorun katana for sitemap)\n")
	fmt.Fprintf(os.Stderr, "  -t        duration      Request timeout (default 10s)\n")
	fmt.Fprintf(os.Stderr, "  -delay    duration      Delay between modules (default 5s)\n")
	fmt.Fprintf(os.Stderr, "  -ri       duration      Explicit delay between requests (overrides rl/rpm)\n")
	fmt.Fprintf(os.Stderr, "  -r        int           Max retries per request (default 3)\n")
	fmt.Fprintf(os.Stderr, "  -rl       int           Requests per second (default 5)\n")
	fmt.Fprintf(os.Stderr, "  -rpm      int           Requests per minute (default 0 = unlimited)\n\n")
	fmt.Fprintf(os.Stderr, "  -H        string        Custom headers\n")
	fmt.Fprintf(os.Stderr, "  -proxy    string        Proxy address (host:port)\n")
	fmt.Fprintf(os.Stderr, "  -m        string        Sitemap path\n")
	fmt.Fprintf(os.Stderr, "  -w        int           Number of parallel request_smugglingers\n\n")
	fmt.Fprintf(os.Stderr, "  -o        string        Output log file (default smuggler.log)\n")
	fmt.Fprintf(os.Stderr, "  -tg-chat  string        Telegram chat ID(overrides default)\n")
	fmt.Fprintf(os.Stderr, "  -tg-report bool         Enable reporting to Telegram\n")
	fmt.Fprintf(os.Stderr, "  -x        bool          Exit after first finding\n")
	fmt.Fprintf(os.Stderr, "  -q        bool          Quiet mode (no banner)\n")
	fmt.Fprintf(os.Stderr, "  -v        bool          Verbose mode\n")
	fmt.Fprintf(os.Stderr, "  -pprof    bool          Pprof server debug purposes\n")
	fmt.Fprintf(os.Stderr, "  -tls      string        TLS impersonation: default|chrome|firefox|safari|edge|random|random-strict\n")
	fmt.Fprintf(os.Stderr, "  -theory   bool          Show advanced theory that yet hard to hadrcode\n")
	fmt.Fprintf(os.Stderr, "  -help                   Show this help\n")
}
