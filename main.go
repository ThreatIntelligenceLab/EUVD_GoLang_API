package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const baseURL = "https://euvdservices.enisa.europa.eu/api"

var limiter = rate.NewLimiter(rate.Every(6*time.Second), 1)
var HTTPClient = &http.Client{Timeout: 10 * time.Second}

func requestWithRateLimit(endpoint string, result interface{}) error {
	if err := limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("rate limit error: %w", err)
	}
	url := fmt.Sprintf("%s%s", baseURL, endpoint)
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return fmt.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad response: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("json decode error: %w", err)
	}
	return nil
}

func prettyPrint(data interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func fetchLatestVulnerabilities() {
	var data []LatestVulnerability
	if err := requestWithRateLimit("/lastvulnerabilities", &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func fetchExploitedVulnerabilities() {
	var data []ExploitedVulnerability
	if err := requestWithRateLimit("/exploitedvulnerabilities", &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func fetchCriticalVulnerabilities() {
	var data []CriticalVulnerability
	if err := requestWithRateLimit("/criticalvulnerabilities", &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func fetchByCVE(reader *bufio.Reader) {
	fmt.Print("Enter CVE ID (e.g., CVE-2024-0864): ")
	cve, _ := reader.ReadString('\n')
	cve = strings.TrimSpace(cve)
	var data VulnerabilityByID
	if err := requestWithRateLimit("/vulnerability?id="+cve, &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func fetchByENISAID(reader *bufio.Reader) {
	fmt.Print("Enter ENISA ID (e.g., EUVD-2024-45012): ")
	id, _ := reader.ReadString('\n')
	id = strings.TrimSpace(id)
	var data ENISAVulnerabilityByID
	if err := requestWithRateLimit("/enisaid?id="+id, &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func fetchAdvisory(reader *bufio.Reader) {
	fmt.Print("Enter Advisory ID (e.g., cisco-sa-ata19x-multi-RDTEqRsy): ")
	id, _ := reader.ReadString('\n')
	id = strings.TrimSpace(id)
	var data AdvisoryByID
	if err := requestWithRateLimit("/advisory?id="+id, &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func searchByText(reader *bufio.Reader) {
	fmt.Print("Enter text to search: ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	var data VulnerabilityQueryResponse
	if err := requestWithRateLimit("/vulnerabilities?text="+text, &data); err != nil {
		log.Println("Error:", err)
		return
	}
	prettyPrint(data)
}

func mainMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\n=== EUVD Tool Menu ===")
		fmt.Println("1. Show Latest Vulnerabilities")
		fmt.Println("2. Show Exploited Vulnerabilities")
		fmt.Println("3. Show Critical Vulnerabilities")
		fmt.Println("4. Search by CVE ID")
		fmt.Println("5. Search by ENISA ID")
		fmt.Println("6. Search by Advisory ID")
		fmt.Println("7. Search vulnerabilities by text")
		fmt.Println("8. Run full self-test")
		fmt.Println("9. Exit")
		fmt.Print("Select an option: ")
		opt, _ := reader.ReadString('\n')
		switch strings.TrimSpace(opt) {
		case "1":
			fetchLatestVulnerabilities()
		case "2":
			fetchExploitedVulnerabilities()
		case "3":
			fetchCriticalVulnerabilities()
		case "4":
			fetchByCVE(reader)
		case "5":
			fetchByENISAID(reader)
		case "6":
			fetchAdvisory(reader)
		case "7":
			searchByText(reader)
		case "8":
			SelfTest()
		case "9":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func SelfTest() bool {
	log.Println("Running self-test against all EUVD API endpoints...")
	file, err := os.Create("test.txt")
	if err != nil {
		log.Printf("Failed to create test.txt: %v", err)
		return false
	}
	defer file.Close()
	success := true

	log.Println("Self-test fetching: Latest Vulnerabilities")
	var latestVulns []LatestVulnerability
	if err := requestWithRateLimit("/lastvulnerabilities", &latestVulns); err != nil {
		log.Printf("Self-test FAILED for Latest Vulnerabilities: %v", err)
		success = false
	} else {
		file.WriteString("===== Latest Vulnerabilities =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(latestVulns)
	}

	log.Println("Self-test fetching: Critical Vulnerabilities")
	var criticalVulns []CriticalVulnerability
	if err := requestWithRateLimit("/criticalvulnerabilities", &criticalVulns); err != nil {
		log.Printf("Self-test FAILED for Critical Vulnerabilities: %v", err)
		success = false
	} else {
		file.WriteString("\n===== Critical Vulnerabilities =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(criticalVulns)
	}

	log.Println("Self-test fetching: Sample Query With Filters")
	var filteredVulns VulnerabilityQueryResponse
	if err := requestWithRateLimit("/vulnerabilities?text=vulnerability", &filteredVulns); err != nil {
		log.Printf("Self-test FAILED for Sample Query With Filters: %v", err)
		success = false
	} else {
		file.WriteString("\n===== Sample Query With Filters =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(filteredVulns)
	}

	log.Println("Self-test fetching: Vulnerability By ID")
	var vulnByID VulnerabilityByID
	if err := requestWithRateLimit("/vulnerability?id=CVE-2024-0864", &vulnByID); err != nil {
		log.Printf("Self-test FAILED for Vulnerability By ID: %v", err)
		success = false
	} else {
		file.WriteString("\n===== Vulnerability By ID =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(vulnByID)
	}

	log.Println("Self-test fetching: ENISA Vulnerability By ID")
	var enisaByID ENISAVulnerabilityByID
	if err := requestWithRateLimit("/enisaid?id=EUVD-2024-45012", &enisaByID); err != nil {
		log.Printf("Self-test FAILED for ENISA Vulnerability By ID: %v", err)
		success = false
	} else {
		file.WriteString("\n===== ENISA Vulnerability By ID =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(enisaByID)
	}

	log.Println("Self-test fetching: Advisory By ID")
	var advisory AdvisoryByID
	if err := requestWithRateLimit("/advisory?id=cisco-sa-ata19x-multi-RDTEqRsy", &advisory); err != nil {
		log.Printf("Self-test FAILED for Advisory By ID: %v", err)
		success = false
	} else {
		file.WriteString("\n===== Advisory By ID =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(advisory)
	}

	log.Println("Self-test fetching: Exploited Vulnerabilities")
	var exploited []ExploitedVulnerability
	if err := requestWithRateLimit("/exploitedvulnerabilities", &exploited); err != nil {
		log.Printf("Self-test FAILED for Exploited Vulnerabilities: %v", err)
		success = false
	} else {
		file.WriteString("\n===== Exploited Vulnerabilities =====\n")
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(exploited)
	}

	if success {
		log.Println("Self-test PASSED: All responses saved to test.txt.")
	} else {
		log.Println("Self-test completed with some FAILED requests. See log for details.")
	}
	return success
}

func main() {
	printBanner()
	mainMenu()
}
