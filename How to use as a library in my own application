
DVB-GSE BBFRAME Defragmentation Tool
This repository contains several small Rust programs demonstrating how to defragment DVB-GSE BBFRAMEs and extract their PDUs (Protocol Data Units).
Each program reads a binary file (sample.bin), passes it through the dvb_gse library for reassembly, and then writes the extracted PDUs to disk.

Requirements
•	Rust (edition 2021 or later recommended)
•	The following crates in your Cargo.toml:

[package]
name = "bbproc"
version = "0.1.0"
edition = "2021"

[dependencies]
dvb-gse = { path = "../dvb-gse-main" }
bytes = "1"
log = "0.4"
env_logger = "0.10"



Input File
The tool expects a file called sample.bin in the current working directory.
This file should contain a DVB BBFRAME that includes one or more GSE fragments.

Code Variants
1. Minimal Extraction
•	File check: Verifies that sample.bin exists.
•	Reading: Loads the file into memory using fs::read().
•	Defragmentation: Passes the data to GSEPacketDefrag.
•	Output:
o	Iterates through PDUs.
o	Prints protocol type and payload length.
o	Saves each PDU to a file named:
o	pdu_<protocol>_<length>.bin
o	Limitation: If multiple PDUs share the same length and protocol, files may be overwritten.
 
2. Output Directory & Unique Filenames
•	Adds output directory: /home/name/Desktop/ (hardcoded).
•	Creates the directory if it does not exist.
•	Uses enumeration (enumerate()) to generate unique filenames, avoiding overwrites:
•	pdu_<protocol>_<length>_<index>.bin
•	Prints the absolute save location for each PDU.
 
3. Hex Preview for Debugging
•	Uses the same output approach as version 2.
•	Adds debug preview: prints the first 16 bytes of each PDU payload in hexadecimal.
•	Example console output:
•	PDU #3 -> protocol=0x0800, len=92 bytes
•	   first 16 bytes: 45 00 00 5c 1c 46 40 00 40 01 ...
•	   saved -> /home/name/Desktop/pdu_0800_92_3.bin
•	Useful for quick inspection of PDU contents before analyzing the full payload.
 
Error Handling
•	If the input file does not exist … prints an error and exits with code 1.
•	If defragmentation fails → prints the error from the dvb_gse library.
•	File writing uses fs::write(); in the minimal version errors are ignored with .ok(), while later versions provide better handling.
 
Improvements & Recommendations
•	Fix hardcoded paths: Replace /home/name/Desktop/ with a configurable output directory (via CLI argument or environment variable).
•	Hex preview: Replace {:02x?} with a proper hex formatter (hex crate or manual join).
•	Error handling: Use ? instead of .ok() to propagate write errors.
•	Efficiency: Replace Bytes::copy_from_slice(&raw) with Bytes::from(raw) to avoid extra memory copy.
 
Example Run
$ cargo run
PDU #0 -> protocol=0x0800, len=92 bytes
   first 16 bytes: 45 00 00 5c 1c 46 40 00 40 01 ...
   saved -> ./pdus_output/pdu_0800_92_0.bin

PDU #1 -> protocol=0x0806, len=28 bytes
   first 16 bytes: 00 01 08 00 06 04 00 01 52 54 ...
   saved -> ./pdus_output/pdu_0806_28_1.bin
 
Summary
•	Version 1: Minimal, direct extraction (risk of file overwriting).
•	Version 2: Safer, writes to desktop with unique filenames.
•	Version 3: Adds debugging hex preview for quick inspection.
This tool is a starting point for working with DVB-GSE BBFRAMEs in Rust.
 
 
