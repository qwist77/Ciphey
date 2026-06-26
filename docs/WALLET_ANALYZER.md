# Wallet Data Analysis and Parsing Tool

## Overview

This tool provides comprehensive analysis and decoding capabilities for cryptocurrency wallet files. It supports multiple wallet formats including Berkeley DB, SQLite, LevelDB, and JSON, with focus on extracting cryptographic material, transaction data, and metadata.

## Features

### Supported Formats
- **Berkeley DB** - Bitcoin Core, Electrum, and other legacy wallet formats
- **SQLite** - Modern wallet databases
- **LevelDB** - Blockchain level DB stores
- **JSON** - Web wallet exports

### Data Extraction
- 🔑 **Cryptocurrency Addresses** - Bitcoin (P2PKH, P2SH), Ethereum, and other blockchain addresses
- 🗝️ **Public Keys** - Compressed and uncompressed Bitcoin public keys, Ethereum keys
- 🔒 **Encrypted Segments** - High-entropy data segments likely containing encrypted private keys
- ⏰ **Timestamps** - Unix timestamps for transaction dating and wallet creation time
- 📝 **Metadata** - Labels, descriptions, and wallet annotations
- 📊 **Entropy Analysis** - Statistical analysis of data sections

### Analysis Capabilities
- Format auto-detection based on file signatures
- Entropy calculation and analysis
- Pattern matching for cryptographic data
- Statistical analysis and extraction

## Installation

### Python Tool (Standalone)
```bash
python wallet_analyzer.py <wallet_file>
```

### Rust Integration
The wallet parser is integrated into the Ciphey Rust codebase:
```rust
use ciphey::decoders::wallet_parser::{WalletParser, WalletFormat};

// Analyze a wallet file
let data = std::fs::read("wallet.dat")?;
let metadata = WalletParser::identify_format(&data);
let extracted = WalletParser::parse_berkeleydb(&data)?;
```

## Usage

### Basic Analysis
```bash
python wallet_analyzer.py wallet.dat
```

Output includes:
- File format identification
- Number of addresses found
- Number of public keys detected
- Timestamp range
- Entropy statistics
- Sample extracted data

### Save Full Report
```bash
python wallet_analyzer.py wallet.dat output.json
```

Creates a detailed JSON report with all extracted data.

## Output Format

### Summary Report
```
======================================================================
WALLET ANALYSIS SUMMARY
======================================================================
File: wallet.dat
Size: 90112 bytes
Format: Berkeley DB v1

[+] FOUND DATA:
  • Addresses: 514
  • Public Keys: 20
  • Encrypted Segments: 0
  • Timestamps: 5272
  • Labels/Metadata: 100

[+] TIMESTAMP RANGE:
  • Earliest: 2009-01-06 08:20:17
  • Latest: 2099-12-21 11:27:04

[+] ENTROPY ANALYSIS:
  • header: 0.69
  • middle: 6.98
  • tail: 2.97
```

### JSON Report
```json
{
  "file_path": "wallet.dat",
  "file_size": 90112,
  "format": "Berkeley DB v1",
  "addresses": ["Bitcoin_P2PKH_013a934e25c2d866...", ...],
  "public_keys": ["020000000000000000...", ...],
  "private_key_segments": [
    {
      "offset": "0x1000",
      "entropy": 7.95,
      "preview": "a3f8e2c9..."
    }
  ],
  "timestamps": [1231006505, 1231006600, ...],
  "labels": ["wallet", "backup", "test", ...],
  "entropy_analysis": {
    "header": 0.69,
    "middle": 6.98,
    "tail": 2.97
  }
}
```

## Technical Details

### Format Detection
The tool uses magic byte signatures to identify wallet formats:
- **Berkeley DB**: Bytes [4:6] == "b1" (variant byte 1)
- **SQLite**: Bytes [0:13] == "SQLite format"
- **LevelDB**: Bytes [0:4] == 0xFF0600

### Address Extraction
- **Bitcoin P2PKH**: Matches pattern `76 a9 14 <20-byte-hash> 88 ac`
- **Bitcoin P2SH**: Matches pattern `a9 14 <20-byte-hash> 87`
- **Ethereum**: Matches `0x` followed by 40 hex characters

### Public Key Patterns
- **Compressed**: 33 bytes starting with 0x02 or 0x03 (32-byte key + prefix)
- **Uncompressed**: 65 bytes starting with 0x04 (64-byte key + prefix)

### Entropy Analysis
Uses Shannon entropy to identify encrypted/compressed sections:
- **Low entropy** (< 3.0): Repetitive or structured data
- **Medium entropy** (3.0-6.0): Mixed or partially structured
- **High entropy** (> 7.0): Encrypted or random data (likely private keys)

### Timestamp Extraction
Searches for 32-bit little-endian Unix timestamps with sanity checks:
- Valid range: 2009-2100 (Bitcoin era)
- Cross-references 64-bit timestamps as well

## Limitations

1. **False Positives**: Binary pattern matching can produce false positives, especially for public key patterns
2. **Encrypted Data**: Cannot recover actual private keys from encrypted segments
3. **Format Variants**: Some custom wallet formats may not be detected
4. **Label Extraction**: ASCII string extraction may capture garbage data

## Security Considerations

⚠️ **IMPORTANT**: 
- This tool is designed for forensic analysis and educational purposes
- Never use extracted private keys without proper validation
- Ensure proper access controls on wallet files
- Use in isolated environments for sensitive analysis
- Output files may contain sensitive information

## Integration with Ciphey

The wallet parser integrates with Ciphey as:
1. A file format detector
2. A data extractor for cryptographic material
3. A format analyzer for blockchain-related challenges
4. An entropy analyzer for mixed encrypted/plaintext files

## Testing

Run the included tests:
```bash
cargo test wallet_parser
```

## Examples

### Example 1: Bitcoin Core Wallet Analysis
```bash
python wallet_analyzer.py ~/.bitcoin/wallets/wallet.dat
```

### Example 2: Ethereum Hardware Wallet Backup
```bash
python wallet_analyzer.py ledger_backup.json
```

### Example 3: Multi-wallet Batch Analysis
```bash
for wallet in wallets/*.dat; do
  python wallet_analyzer.py "$wallet" "${wallet}_report.json"
done
```

## References

- [Bitcoin Wallet Formats](https://en.bitcoin.it/wiki/Wallet_import_format)
- [Berkeley DB Format](https://docs.oracle.com/cd/E17076_05/html/gsg/C/intro.html)
- [Ethereum Key Formats](https://eth-keys.readthedocs.io/)
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))

## Contributing

To add support for new wallet formats:
1. Add format detection in `identify_format()`
2. Implement parser in new `parse_*` method
3. Update format enum and metadata
4. Add tests for the new format

## License

MIT - See LICENSE file

## Author

Copilot - Automated Decoding Tool
Part of the Ciphey project (https://github.com/bee-san/ciphey)
