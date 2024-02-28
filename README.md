# VTScraper

VTScraper is a Python script for scraping and parsing file details and behavior analysis from VirusTotal using Selenium and the PyShadow library for handling shadow DOM elements.

## Installation

1. Clone this repository:
```
git clone https://github.com/<your-username>/VTScraper.git
```
2. Navigate into the project directory:
```
cd VTScraper
```
3. Install required dependencies:
```
pip install -r requirements.txt
```

## Usage

To run VTScraper, you have two main options:

1. Process a single hash:
```
python vts.py --hash <target-hash>
```

2. Process multiple hashes from a CSV file:
```
python vts.py --csv <path-to-csv>
```

The CSV file should contain target hashes in the first column.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.