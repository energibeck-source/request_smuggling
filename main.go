package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"request_smuggling/core"
	"request_smuggling/modules"
	"request_smuggling/notify"
	"request_smuggling/theory"
)

func setupLogging(outputPath string) *os.File {
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return f
}

func main() {
	opts := core.ParseOptions()

	if opts.Theory {
		theory.RunViewer()
		return
	}

	logFile := setupLogging(opts.OutputFile)
	defer logFile.Close()

	target := opts.Target
	fmt.Printf("Scanning %s\n", target.Host)

	var h2Base core.NormalResponse
	var err error
	if target.TLS {
		h2Base, err = core.H2Baseline(target)
		if err != nil {
			log.Printf("H2 baseline failed: %v", err)
		} else if h2Base.Error != nil {
			log.Printf("H2 baseline error: %v", h2Base.Error)
		} else {
			log.Printf("H2 baseline: %v", h2Base)
		}
	}

	requester := &core.SimpleRequester{
		Timeout:      opts.Timeout,
		RateInterval: opts.RateInterval,
	}

	ctx := core.ScanContext{
		Target:  target,
		Options: opts,
	}

	runner := core.Runner{
		Modules:    make([]core.Module, 0),
		ExitOnFind: opts.ExitOnFind,
	}

	runner.Modules = SelectModules(opts.Tech, requester, opts.Timeout)

	if opts.CSAHost != "" {
		for _, mod := range runner.Modules {
			if cs, ok := mod.(*modules.ConnStateModule); ok {
				cs.AltHost = opts.CSAHost
			}
		}
	}

	delay := opts.Delay

	for i, rec := range target.Sitemap {

		allowed, err := core.InitialRecon(rec)
		if err != nil {
			log.Printf("Error while running initial recon for endpoint %s: %v\n", rec.Request.Endpoint, err)
			rec.Result.ProtocolVersions = []string{}
			target.Sitemap[i] = rec
			continue
		}

		if allowed != nil {
			rec.Result.ProtocolVersions = allowed
		} else {
			rec.Result.ProtocolVersions = []string{}
		}
		target.Sitemap[i] = rec
	}

	findings := runner.RunAll(ctx, delay)

	resultsPath := core.ArtifactPath("results.jsonl")
	err = core.SaveSitemap(target.Sitemap, resultsPath)
	if err != nil {
		log.Println("Error during saving sitemap: ", err)
	} else {
		fmt.Println("Results saved in " + resultsPath)
	}

	chatID := os.Getenv("GT_L")
	if opts.TelegramChatID != "" {
		chatID = opts.TelegramChatID
	}
	notifier := notify.NewTelegramNotifier(chatID)

	if len(findings) > 0 {
		head := fmt.Sprintf("Findings for %s:\n", target)
		fmt.Println(head)

		var report string
		report += head + "\n"
		for _, f := range findings {
			line := fmt.Sprintf("  [%s] %s: %s\nEvidense: %s", f.Severity, f.Module, f.Details, f.Evidence)
			fmt.Println(line)
			report += line + "\n"
		}

		if err := notifier.SendReport(report); err != nil {
			log.Printf("telegram send error: %v", err)
		}
	} else {
		fmt.Printf("Nothing interesting found for target %s\n", target.Host)
	}
}

type ModuleConstructor func(*core.SimpleRequester, time.Duration) core.Module

var ModuleRegistry = map[string]ModuleConstructor{
	"clte": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.CLTEModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"tecl": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.TECLModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"tete": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.TETEModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"0cl": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.ZeroCLModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"cl0": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.CLZeroModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"h20": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		_ = req
		return &modules.H2ZeroModule{
			Timeout: timeout,
		}
	},
	"connstate": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.ConnStateModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"expect": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.ExpectModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"chunkext": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.ChunkExtModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"headermatrix": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.HeaderMatrixModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"te0": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		return &modules.TEZeroModule{
			Requester: req,
			Timeout:   timeout,
		}
	},
	"h2te": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		_ = req
		return &modules.H2TEModule{
			Timeout: timeout,
		}
	},
	"h2cl_ignore": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		_ = req
		return &modules.H2CL_ignoreModule{
			Timeout: timeout,
		}
	},
	"h2crlf ": func(req *core.SimpleRequester, timeout time.Duration) core.Module {
		_ = req
		return &modules.H2CRLFInj{
			Timeout: timeout,
		}
	},
}

func SelectModules(tech string, requester *core.SimpleRequester, timeout time.Duration) []core.Module {
	var modules []core.Module

	if tech == "all" {
		for _, constructor := range ModuleRegistry {
			modules = append(modules, constructor(requester, timeout))
		}
		return modules
	}

	techs := strings.Split(tech, ",")
	selected := make(map[string]bool)

	for _, t := range techs {
		t = strings.TrimSpace(strings.ToLower(t))
		if t == "" {
			continue
		}

		if constructor, ok := ModuleRegistry[t]; ok {
			modules = append(modules, constructor(requester, timeout))
			selected[t] = true
			continue
		}

		for name, constructor := range ModuleRegistry {
			if selected[name] {
				continue
			}
			if strings.Contains(strings.ToLower(name), t) {
				modules = append(modules, constructor(requester, timeout))
				selected[name] = true
			}
		}
	}

	return modules
}
