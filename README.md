# 🔐 EUVD CLI Lookup Tool

A powerful command-line tool built in Go that allows cybersecurity professionals to search, filter, and inspect vulnerability data directly from the [ENISA EUVD API](https://euvdservices.enisa.europa.eu/).

> Built for analysts. Powered by open intelligence. 🇪🇺

---

## ✨ Features

- ✅ View latest vulnerabilities
- ✅ View exploited & critical vulnerabilities
- ✅ Search by:
  - CVE ID
  - ENISA ID
  - Advisory ID
  - Text keywords
- ✅ Run a complete self-test against all endpoints
- ✅ Pretty-printed output
- ✅ Automatic rate-limiting (1 request per 6s)

---

## 📦 Installation

```bash
git clone this repo
cd to the local repo
go build -o euvd
````

---

## 🚀 Usage

Run the binary:

```bash
./euvd
```

You'll be greeted with a menu like:

```
=== EUVD Tool Menu ===
1. Show Latest Vulnerabilities
2. Show Exploited Vulnerabilities
3. Show Critical Vulnerabilities
4. Search by CVE ID
5. Search by ENISA ID
6. Search by Advisory ID
7. Search vulnerabilities by text
8. Run full self-test
9. Exit
Select an option:
```

Just enter the number of the desired operation and follow the prompts.

---

## 🧪 Self-Test

Want to verify your installation and the health of the ENISA API?

Run:

```
8. Run full self-test
```

All results will be saved to a file called `test.txt`.

---

## 🔧 Development

To edit or extend functionality:

* All struct definitions are in `structs.go`
* Main logic is in `main.go`
* API source: [https://euvdservices.enisa.europa.eu/api](https://euvdservices.enisa.europa.eu/api)

 
---

## 🙏 Credits

Made with ❤️ by [threatintelligencelab.com](https://threatintelligencelab.com)

Follow our LinkedIn page [here](https://www.linkedin.com/company/threat-intelligence-lab/) ❤️


