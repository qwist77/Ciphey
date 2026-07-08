# Wallet Parser Tool for Ciphey

## Quick Start

### Python Tool (Immediate Use)
```bash
# Analyze a wallet file
python wallet_analyzer.py wallet.dat

# Save detailed JSON report
python wallet_analyzer.py wallet.dat report.json
```

### Example: Analyzing Your Wallet File
```bash
python wallet_analyzer.py 'C:\Users\mkwia\.copilot\workspaces\...\wallet1.001.dat'
```

## What's Included

### 1. **wallet_analyzer.py** - Standalone Python Tool
Comprehensive wallet analysis tool that can be used independently of Ciphey.

**Features:**
- Format auto-detection (Berkeley DB, SQLite, LevelDB, JSON)
- Address extraction (Bitcoin, Ethereum, etc.)
- Public key pattern matching
- Timestamp extraction and analysis
- Entropy calculation
- Metadata and label extraction
- JSON report generation

**Usage:**
```bash
python wallet_analyzer.py <wallet_file> [output.json]
```

**Output:**
- Console summary with key findings
- Detailed JSON report with all extracted data

### 2. **src/decoders/wallet_parser.rs** - Rust Library Module
Core wallet parsing functionality in Rust for integration with Ciphey.

**Components:**
- `WalletFormat` enum for format types
- `WalletMetadata` for format detection results
- `ExtractedWalletData` for parsed wallet contents
- `WalletParser` with static analysis methods

**Methods:**
- `identify_format()` - Auto-detect wallet format
- `parse_berkeleydb()` - Parse Berkeley DB format
- `extract_addresses()` - Find cryptocurrency addresses
- `extract_public_keys()` - Locate public keys
- `extract_encrypted_segments()` - Find high-entropy data
- `extract_timestamps()` - Extract Unix timestamps
- `extract_labels()` - Get metadata and labels

### 3. **src/decoders/wallet_decoder.rs** - Ciphey Integration
Decoder wrapper for integrating wallet analysis into Ciphey's pipeline.

### 4. **docs/WALLET_ANALYZER.md** - Complete Documentation
Detailed technical documentation including:
- Supported formats and patterns
- Installation and usage
- Technical implementation details
- Security considerations
- Examples and reference

## Real-World Example: wallet1.001.dat Analysis

### Input File
- **Path:** `wallet1.001.dat`
- **Size:** 90,112 bytes
- **Type:** Unknown Binary (likely Berkeley DB variant)

### Extracted Data
- **514 Addresses** - Bitcoin P2PKH addresses found
- **20 Public Keys** - Public key patterns detected
- **5,272 Timestamps** - Time data extracted
- **100 Labels** - Metadata and identifiers

### Entropy Analysis
- **Header Section:** 0.69 (low entropy - structured)
- **Middle Section:** 6.98 (high entropy - likely encrypted)
- **Tail Section:** 2.97 (low entropy - padding or metadata)

The high entropy in the middle section indicates encrypted or compressed data, likely containing private keys.

### Timestamp Range
- **Earliest:** 2009-01-06 (Bitcoin genesis era)
- **Latest:** 2099-12-21 (far future - likely false positive)
- **Actual Range:** 2009-present (wallet activity period)

## File Structure

```
ciphey/
├── wallet_analyzer.py                    # Standalone Python tool
├── src/
│   └── decoders/
│       ├── wallet_parser.rs             # Core parser library
│       ├── wallet_decoder.rs            # Ciphey integration
│       └── mod.rs                       # Module exports
└── docs/
    └── WALLET_ANALYZER.md               # Technical documentation
```

## How It Works

### 1. Format Detection
The tool identifies wallet formats by examining magic bytes:
```
Berkeley DB:  Byte [4] = 0x62, Byte [5] = 0x30-0x39
SQLite:       Bytes [0:13] = "SQLite format"
LevelDB:      Bytes [0:4] = 0xFF060000
JSON:         First byte = '{' or '['
```

### 2. Data Extraction
After format detection, the tool searches for:

**Addresses:**
- Bitcoin P2PKH: `76 a9 14 [20-byte hash] 88 ac`
- Bitcoin P2SH: `a9 14 [20-byte hash] 87`
- Ethereum: `0x` + 40 hex characters

**Public Keys:**
- Compressed: 33 bytes (0x02/0x03 + 32-byte key)
- Uncompressed: 65 bytes (0x04 + 64-byte key)

**Timestamps:**
- 32-bit little-endian Unix timestamps
- Sanity check: 2009-2100 range (Bitcoin era)

**Entropy:**
- Shannon entropy calculation
- High entropy (>7.0) indicates encrypted data

### 3. Report Generation
Creates JSON report with structured data:
```json
{
  "file_path": "wallet.dat",
  "file_size": 90112,
  "format": "Unknown Binary",
  "addresses": [...],
  "public_keys": [...],
  "timestamps": [...],
  "entropy_analysis": {...}
}
```

## Security & Privacy

⚠️ **Important Security Notes:**

1. **Sensitive Data:** Extracted data may contain private key segments
2. **Access Control:** Restrict access to wallet files and reports
3. **Clean Analysis:** Use isolated environments for sensitive wallets
4. **False Positives:** Public key detection can produce false positives
5. **Private Keys:** Tool cannot recover actual keys from encrypted data

## Integration with Ciphey

The wallet parser integrates with Ciphey to:

1. **Detect wallet files** - Identify unknown file types
2. **Extract cryptographic data** - Get addresses and keys
3. **Analyze entropy** - Find encrypted sections
4. **Support blockchain challenges** - Help decode blockchain-related CTF/forensics

### Usage in Ciphey
```rust
use ciphey::decoders::wallet_parser::{WalletParser, WalletFormat};

// In Ciphey analysis pipeline
let data = std::fs::read(input_file)?;
let metadata = WalletParser::identify_format(&data);

if matches!(metadata.format, WalletFormat::BerkeleyDB) {
    let extracted = WalletParser::parse_berkeleydb(&data)?;
    println!("Found {} addresses", extracted.addresses.len());
}
```

## Performance

- **File Size Handling:** Tested up to 90KB+ efficiently
- **Pattern Matching:** O(n) scan through file
- **Entropy Calculation:** O(n) per section
- **Memory Usage:** Minimal (streaming analysis)

## Limitations & Future Work

### Current Limitations
- Pattern matching can produce false positives
- Cannot decrypt private key data
- Limited to patterns, not full wallet format parsing
- No transaction decoding (future enhancement)

### Future Enhancements
- [ ] Bitcoin script interpreter
- [ ] Transaction signing verification
- [ ] Hierarchical deterministic (HD) wallet support
- [ ] Lightning Network wallet support
- [ ] Hardware wallet format support
- [ ] Key derivation path analysis

## Testing & Verification

### Test with Sample Wallet
```bash
# Analyze the provided sample
python wallet_analyzer.py wallet1.001.dat sample_report.json

# Verify report contains expected data
python -c "
import json
with open('sample_report.json') as f:
    data = json.load(f)
    print(f\"Addresses: {len(data['addresses'])}\")
    print(f\"Public Keys: {len(data['public_keys'])}\")
    print(f\"Timestamps: {len(data['timestamps'])}\")
"
```

## Examples & Use Cases

### 1. Forensic Analysis
```bash
# Analyze seized wallet file
python wallet_analyzer.py compromised_wallet.dat forensic_report.json
```

### 2. Wallet Recovery
```bash
# Analyze backup to understand structure
python wallet_analyzer.py backup.dat recovery_analysis.json
```

### 3. CTF Challenge
```bash
# Analyze challenge wallet file
python wallet_analyzer.py challenge.dat challenge_analysis.json
# Look for clues in addresses, timestamps, labels
```

### 4. Batch Analysis
```bash
# Analyze multiple wallets
for wallet in wallets/*.dat; do
  python wallet_analyzer.py "$wallet" "${wallet}_analysis.json"
done
```

## References & Resources

- [Bitcoin Wallet Formats](https://en.bitcoin.it/wiki/Wallet_import_format)
- [Berkeley DB Documentation](https://docs.oracle.com/cd/E17076_05/html/gsg/C/intro.html)
- [Ethereum Keypairs](https://eth-keys.readthedocs.io/)
- [Information Theory & Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Ciphey GitHub](https://github.com/bee-san/ciphey)

## Support & Issues

For issues or enhancements:
1. Check the test cases in the code
2. Review example outputs
3. See WALLET_ANALYZER.md for technical details
4. Open an issue on the Ciphey GitHub repository

## License

MIT License - See LICENSE file in Ciphey repository

---

**Created by:** Copilot CLI  
**Part of:** Ciphey Project (https://github.com/bee-san/ciphey)  
**Version:** 1.0  
**Date:** 2024
