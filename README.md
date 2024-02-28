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
OUTPUT:
Attempt 1: Getting details from https://www.virustotal.com/gui/file/7f59ae781bd4355ea07450d8aca5f68ae18642b70abbf04f0cd8d72743e059c9/details
File details for 7f59ae781bd4355ea07450d8aca5f68ae18642b70abbf04f0cd8d72743e059c9:
```python
{
    "MD5": "3b6c915658b74fe1efa43545d59a8a91",
    "SHA-1": "e0fb405aab45ac201e9b7e70fafab068635048db",
    "SHA-256": "7f59ae781bd4355ea07450d8aca5f68ae18642b70abbf04f0cd8d72743e059c9",
    "Vhash": "064056655d655d70d8z447z37z13z25zd7z",
    "Authentihash": "11f6427edc5f078c950cefb675892093acab13faeed741f960338f3d89f9d5d5",
    "Imphash": [
        "851a0ba8fbb71710075bdfe6dcef92eb",
        "Rich PE header hash",
        "256b60751602028612562b73ecdb163c"
    ],
    "SSDEEP": "1536:wNeRBl5PT/rx1mzwRMSTdLpJ1vAl0mgEO2leiYBk:wQRrmzwR5J+gbWeZ",
    "TLSH": "T17953DF06746C54B2CEB58670293A6B5F9FBE560240B4844B4F3D4E9A3ED5032E73E376",
    "File type": [
        "Win32 EXE",
        "executable",
        "windows",
        "win32",
        "pe",
        "peexe"
    ],
    "Magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
    "TrID": "Win64 Executable (generic) (30.2%)   Win32 Dynamic Link Library (generic) (18.9%)   Win16 NE executable (generic) (14.5%)",
    "DetectItEasy": "PE32   Compiler: Microsoft Visual C/C++ (16.00.40219) [LTCG/C]   Linker: Microsoft Linker (10.00.40219)",
    "File size": "61.00 KB (62464 bytes)",
    "Creation Time": "2020-03-31 14:17:25 UTC",
    "First Seen In The Wild": "2024-02-14 03:49:43 UTC",
    "First Submission": "2024-02-04 11:00:52 UTC",
    "Last Submission": "2024-02-04 11:00:52 UTC",
    "Last Analysis": [
        "2024-02-09 11:46:12 UTC",
        "antirecuvadb.exe",
        "software.exe",
        "AntiRecuvaDB.exe.1"
    ],
    "Compiler Products": [
        "[ C ] VS2008 SP1 build 30729 count=1",
        "[IMP] VS2008 SP1 build 30729 count=19",
        "[---] Unmarked objects count=111",
        "[ASM] VS2010 SP1 build 40219 count=1",
        "[ C ] VS2010 SP1 build 40219 count=1",
        "[LNK] VS2010 SP1 build 40219 count=1",
        "id: 0xae, version: 40219 count=18"
    ],
    "Header": {
        "Info": {
            "Target Machine": "Intel 386 or later processors and compatible processors",
            "Compilation Timestamp": "2020-03-31 14:17:25 UTC",
            "Entry Point": "12199",
            "Contained Sections": "5"
        },
        "Sections": [
            {
                "Name": ".text",
                "Virtual": "34304",
                "Address": "34200",
                "Size": "165247.25",
                "Raw": "a491c4d91a4b5889442e891da7aad09f",
                "Entropy": "N/A",
                "MD5": "N/A",
                "Chi2": "N/A"
            },
            {
                "Name": ".rdata",
                "Virtual": "4096",
                "Address": "3708",
                "Size": "124785.38",
                "Raw": "a73fadb324bbeec4e8315214d839bd02",
                "Entropy": "N/A",
                "MD5": "N/A",
                "Chi2": "N/A"
            },
            {
                "Name": ".data",
                "Virtual": "1536",
                "Address": "9913",
                "Size": "38487.2",
                "Raw": "49712d83df01207463982caea3157486",
                "Entropy": "N/A",
                "MD5": "N/A",
                "Chi2": "N/A"
            },
            {
                "Name": ".reloc",
                "Virtual": "1536",
                "Address": "1518",
                "Size": "31901.55",
                "Raw": "63531957a01468434c794b6b08c13046",
                "Entropy": "N/A",
                "MD5": "N/A",
                "Chi2": "N/A"
            },
            {
                "Name": ".cdata",
                "Virtual": "19968",
                "Address": "19576",
                "Size": "10989.8",
                "Raw": "8948151844ee1989efbc97805c18b3f6",
                "Entropy": "N/A",
                "MD5": "N/A",
                "Chi2": "N/A"
            }
        ]
    },
    "Imports": [
        "MPR.dll",
        "IPHLPAPI.DLL",
        "SHELL32.dll",
        "KERNEL32.dll",
        "ADVAPI32.dll",
        "ole32.dll",
        "WS2_32.dll",
        "USER32.dll",
        "WINHTTP.dll"
    ]
}
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
