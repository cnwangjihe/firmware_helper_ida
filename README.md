# Firmware Analyze Helper for IDA Pro

A small script extracted from my undergraduate thesis, which can assist the analyzing of ARM32 firmware.  
Offers the following features:  

1. Automatically analyzes the program's base address based on the interrupt vector table and rebases the entire IDA database without needing a datasheet.  
2. Performs linear function scanning.  

## Usage

Install `capstone` in your ida python first.  

Load your firmware into IDA Pro, choose the right processor and architecture, and use File -> Script File to run `ida_analyze.py`.

