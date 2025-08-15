# Brainwave_Matrix_Intern

# 🛡️ Phishing URL Scanner - Brainwave Matrix Internship Project

This project is part of the Brainwave Matrix Internship. It is a Python-based phishing URL detection tool that uses heuristics and typo-squatting analysis to detect suspicious links.

## 🔍 Features
- ✅ Detects typo-squatting (e.g., `faceboook.com`)
- 🛑 Checks for dangerous characters and patterns
- ⚠️ Flags punycode and IP-based URLs
- 📏 Scores URLs using heuristic rules

## 📦 Requirements
- Python 3.7+
- `tldextract`
- `python-Levenshtein`

Install dependencies:
```bash
pip install -r requirements.txt
