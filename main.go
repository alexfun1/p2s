package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"cloud.google.com/go/pubsub"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Vulnerability struct {
	Severity     string `json:"severity"`
	Type         string `json:"type"` // "OS" or "APP"
	Description  string `json:"description"`
	PackageName  string `json:"package_name"`
	ResourceName string `json:"resource_name"`
}

type Config struct {
	OSChannelName  string
	OSMinSeverity  string
	AppChannelName string
	AppMinSeverity string
	Mutex          sync.RWMutex
}

var config = Config{
	OSChannelName:  "#os-vulns",
	OSMinSeverity:  "MEDIUM",
	AppChannelName: "#app-vulns",
	AppMinSeverity: "HIGH",
}

var severityLevels = map[string]int{
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

var vulnCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vulnerability_reports_total",
		Help: "Total number of vulnerability reports by severity and type",
	},
	[]string{"severity", "type"},
)

func main() {
	prometheus.MustRegister(vulnCounter)

	go startWebServer()
	go startPubSubListener()

	select {}
}

func startWebServer() {
	r := gin.Default()
	tmpl := template.Must(template.ParseFiles("config.html"))
	r.GET("/config", func(c *gin.Context) {
		config.Mutex.RLock()
		defer config.Mutex.RUnlock()
		tmpl.Execute(c.Writer, config)
	})
	r.POST("/config", func(c *gin.Context) {
		config.Mutex.Lock()
		defer config.Mutex.Unlock()
		config.OSChannelName = c.PostForm("os_channel")
		config.OSMinSeverity = c.PostForm("os_severity")
		config.AppChannelName = c.PostForm("app_channel")
		config.AppMinSeverity = c.PostForm("app_severity")
		c.Redirect(http.StatusSeeOther, "/config")
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.Run(":8080")
}

func startPubSubListener() {
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, os.Getenv("GCP_PROJECT"))
	if err != nil {
		log.Fatalf("Failed to create pubsub client: %v", err)
	}
	sub := client.Subscription(os.Getenv("PUBSUB_SUBSCRIPTION"))
	sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		var v Vulnerability
		if err := json.Unmarshal(msg.Data, &v); err != nil {
			log.Printf("Invalid message format: %v", err)
			msg.Nack()
			return
		}

		vulnCounter.WithLabelValues(v.Severity, v.Type).Inc()
		processVulnerability(v)
		msg.Ack()
	})
}

func processVulnerability(v Vulnerability) {
	config.Mutex.RLock()
	defer config.Mutex.RUnlock()

	severityRank := severityLevels[strings.ToUpper(v.Severity)]

	if v.Type == "OS" && severityRank >= severityLevels[config.OSMinSeverity] {
		sendToSlack(config.OSChannelName, v)
	} else if v.Type == "APP" && severityRank >= severityLevels[config.AppMinSeverity] {
		sendToSlack(config.AppChannelName, v)
	}
}

/* This function sends a formatted message to a Slack channel.
func sendToSlack(channel string, v Vulnerability) {
	message := map[string]interface{}{
		"channel": channel,
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf(
						"*Vulnerability Alert*\n*Severity:* `%s`\n*Type:* `%s`\n*Package:* `%s`\n*Resource:* `%s`\n*Description:* %s",
						v.Severity,
						v.Type,
						v.PackageName,
						v.ResourceName,
						v.Description,
					),
				},
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal Slack payload: %v", err)
		return
	}

	resp, err := http.Post(os.Getenv("SLACK_WEBHOOK"), "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Printf("Failed to send Slack notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("Slack returned non-200 status: %s", resp.Status)
	}
}
*/

// This function sends a formatted message to a Slack channel with a link to the GCP Security Command Center.

func sendToSlack(channel string, v Vulnerability) {
	projectID := os.Getenv("GCP_PROJECT")

	// Construct a GCP Security Command Center console URL (adjust format if needed)
	sccLink := fmt.Sprintf(
		"https://console.cloud.google.com/security/command-center/findings?project=%s&resourceName=%s",
		projectID,
		url.QueryEscape(v.ResourceName),
	)

	message := map[string]interface{}{
		"channel": channel,
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf(
						"*Vulnerability Alert*\n*Severity:* `%s`\n*Type:* `%s`\n*Package:* `%s`\n*Resource:* `%s`\n*Description:* %s",
						v.Severity,
						v.Type,
						v.PackageName,
						v.ResourceName,
						v.Description,
					),
				},
			},
			{
				"type": "actions",
				"elements": []map[string]interface{}{
					{
						"type": "button",
						"text": map[string]string{
							"type": "plain_text",
							"text": "View in GCP SCC",
						},
						"url": sccLink,
					},
				},
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		log.Printf("Failed to marshal Slack payload: %v", err)
		return
	}

	resp, err := http.Post(os.Getenv("SLACK_WEBHOOK"), "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Printf("Failed to send Slack notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("Slack returned non-200 status: %s", resp.Status)
	}
}
