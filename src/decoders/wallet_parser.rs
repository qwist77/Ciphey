/// Wallet parser module for analyzing and decoding cryptocurrency wallet files
/// Supports Bitcoin, Ethereum, and other blockchain wallet formats
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Cursor};

#[derive(Debug, Clone, PartialEq)]
pub enum WalletFormat {
    BerkeleyDB,
    LevelDB,
    SQLite,
    JSON,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct WalletMetadata {
    pub format: WalletFormat,
    pub size: u64,
    pub signatures: Vec<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExtractedWalletData {
    pub addresses: Vec<String>,
    pub public_keys: Vec<String>,
    pub encrypted_keys: Vec<Vec<u8>>,
    pub timestamps: Vec<u64>,
    pub labels: Vec<String>,
    pub transactions: Vec<WalletTransaction>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct WalletTransaction {
    pub hash: String,
    pub timestamp: u64,
    pub amount: Option<String>,
    pub from_address: Option<String>,
    pub to_address: Option<String>,
}

impl fmt::Display for WalletMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wallet Metadata:\n  Format: {:?}\n  Size: {} bytes\n  Signatures: {:?}\n  Version: {:?}",
            self.format, self.size, self.signatures, self.version
        )
    }
}

impl fmt::Display for ExtractedWalletData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Extracted Wallet Data:")?;
        writeln!(f, "  Addresses found: {}", self.addresses.len())?;
        if !self.addresses.is_empty() {
            for addr in &self.addresses[..self.addresses.len().min(5)] {
                writeln!(f, "    - {}", addr)?;
            }
            if self.addresses.len() > 5 {
                writeln!(f, "    ... and {} more", self.addresses.len() - 5)?;
            }
        }
        
        writeln!(f, "  Public keys found: {}", self.public_keys.len())?;
        writeln!(f, "  Encrypted key segments: {}", self.encrypted_keys.len())?;
        writeln!(f, "  Timestamps found: {}", self.timestamps.len())?;
        writeln!(f, "  Labels found: {}", self.labels.len())?;
        writeln!(f, "  Transactions: {}", self.transactions.len())?;
        Ok(())
    }
}

pub struct WalletParser;

impl WalletParser {
    /// Identify wallet file format from magic bytes and signatures
    pub fn identify_format(data: &[u8]) -> WalletMetadata {
        let mut signatures = Vec::new();
        let mut format = WalletFormat::Unknown;
        let mut version = None;

        // Check for Berkeley DB format (b0, b1, b2, etc.)
        if data.len() > 4 {
            if data[4] == 0x62 && (data[5] >= 0x30 && data[5] <= 0x39) {
                format = WalletFormat::BerkeleyDB;
                signatures.push(format!("Berkeley DB v{}", (data[5] as char)));
                version = Some(format!("v{}", (data[5] as char)));
            }
        }

        // Check for SQLite format
        if data.len() > 16 && &data[0..13] == b"SQLite format" {
            format = WalletFormat::SQLite;
            signatures.push("SQLite Header".to_string());
        }

        // Check for JSON format
        if data.len() > 0 && (data[0] == b'{' || data[0] == b'[') {
            format = WalletFormat::JSON;
            signatures.push("JSON".to_string());
        }

        // Check for LevelDB format
        if data.len() > 4 && &data[0..4] == b"\xFF\x06\x00\x00" {
            format = WalletFormat::LevelDB;
            signatures.push("LevelDB".to_string());
        }

        WalletMetadata {
            format,
            size: data.len() as u64,
            signatures,
            version,
        }
    }

    /// Parse Berkeley DB wallet format
    pub fn parse_berkeleydb(data: &[u8]) -> Result<ExtractedWalletData, String> {
        let mut extracted = ExtractedWalletData {
            addresses: Vec::new(),
            public_keys: Vec::new(),
            encrypted_keys: Vec::new(),
            timestamps: Vec::new(),
            labels: Vec::new(),
            transactions: Vec::new(),
            metadata: HashMap::new(),
        };

        let mut cursor = Cursor::new(data);
        
        // Parse Berkeley DB header
        let mut magic = [0u8; 5];
        if cursor.read_exact(&mut magic).is_ok() {
            extracted.metadata.insert(
                "magic_bytes".to_string(),
                format!("{:02x?}", magic),
            );
        }

        // Scan for common patterns
        extracted.addresses = Self::extract_addresses(data);
        extracted.public_keys = Self::extract_public_keys(data);
        extracted.encrypted_keys = Self::extract_encrypted_segments(data);
        extracted.timestamps = Self::extract_timestamps(data);
        extracted.labels = Self::extract_labels(data);

        Ok(extracted)
    }

    /// Extract cryptocurrency addresses (Bitcoin, Ethereum, etc.)
    pub fn extract_addresses(data: &[u8]) -> Vec<String> {
        let mut addresses = Vec::new();
        
        // Bitcoin address patterns (P2PKH, P2SH)
        for i in 0..data.len().saturating_sub(33) {
            // P2PKH starts with 0x76 0xa9 0x14 (OP_DUP OP_HASH160 0x14)
            if i + 3 < data.len() && data[i] == 0x76 && data[i + 1] == 0xa9 && data[i + 2] == 0x14 {
                let hash160 = &data[i + 3..i + 23];
                let addr = Self::hash160_to_address(hash160);
                if !addresses.contains(&addr) {
                    addresses.push(addr);
                }
            }
        }

        // Ethereum addresses (0x followed by 40 hex chars) - look for 0x prefix
        for window in data.windows(42) {
            if window[0] == b'0' && window[1] == b'x' {
                if let Ok(hex_str) = std::str::from_utf8(&window[2..]) {
                    if hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
                        let addr = format!("0x{}", hex_str);
                        if !addresses.contains(&addr) {
                            addresses.push(addr);
                        }
                    }
                }
            }
        }

        addresses
    }

    /// Extract public key patterns
    pub fn extract_public_keys(data: &[u8]) -> Vec<String> {
        let mut public_keys = Vec::new();

        // Bitcoin compressed public keys (33 bytes: 02 or 03 + 32 bytes)
        for i in 0..data.len().saturating_sub(32) {
            if (data[i] == 0x02 || data[i] == 0x03) && i + 33 <= data.len() {
                let hex = format!("{:02x}{}", data[i], 
                    Self::bytes_to_hex(&data[i + 1..i + 33]));
                if !public_keys.contains(&hex) {
                    public_keys.push(hex);
                }
            }
        }

        // Bitcoin uncompressed public keys (65 bytes: 04 + 64 bytes)
        for i in 0..data.len().saturating_sub(64) {
            if data[i] == 0x04 && i + 65 <= data.len() {
                let hex = format!("04{}", Self::bytes_to_hex(&data[i + 1..i + 65]));
                if !public_keys.contains(&hex) {
                    public_keys.push(hex);
                }
            }
        }

        public_keys
    }

    /// Extract encrypted key segments
    pub fn extract_encrypted_segments(data: &[u8]) -> Vec<Vec<u8>> {
        let mut segments = Vec::new();

        // Look for high entropy segments (typically encrypted data)
        for window in data.windows(32) {
            let entropy = Self::calculate_entropy(window);
            if entropy > 7.0 {
                segments.push(window.to_vec());
            }
        }

        segments
    }

    /// Extract timestamps (little-endian 32-bit Unix timestamps)
    pub fn extract_timestamps(data: &[u8]) -> Vec<u64> {
        let mut timestamps = Vec::new();

        for i in (0..data.len().saturating_sub(3)).step_by(4) {
            if i + 4 <= data.len() {
                let ts = u32::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                ]) as u64;

                // Sanity check: reasonable timestamp range (2009-2100)
                if ts > 1231006505 && ts < 4102444800 {
                    timestamps.push(ts);
                }
            }
        }

        timestamps.sort();
        timestamps.dedup();
        timestamps
    }

    /// Extract human-readable labels and metadata
    pub fn extract_labels(data: &[u8]) -> Vec<String> {
        let mut labels = Vec::new();

        for i in 0..data.len().saturating_sub(5) {
            if let Ok(text) = std::str::from_utf8(&data[i..i.min(data.len())]) {
                for word in text.split_whitespace() {
                    if word.len() >= 3 && word.len() <= 128 {
                        if word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                            if !labels.contains(&word.to_string()) {
                                labels.push(word.to_string());
                            }
                        }
                    }
                }
            }
        }

        labels
    }

    /// Convert hash to hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Calculate Shannon entropy of a byte slice
    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut freq = [0usize; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Convert HASH160 (Bitcoin script) to address
    fn hash160_to_address(hash: &[u8]) -> String {
        // This is a simplified version - real Bitcoin address generation requires base58check
        format!("Bitcoin_Address_{}", hex::encode(hash))
    }

    /// Parse extracted data into human-readable format
    pub fn to_json(&self, data: &ExtractedWalletData) -> serde_json::Value {
        serde_json::json!({
            "addresses_count": data.addresses.len(),
            "addresses": data.addresses,
            "public_keys_count": data.public_keys.len(),
            "public_keys": data.public_keys,
            "encrypted_segments": data.encrypted_keys.len(),
            "timestamps_count": data.timestamps.len(),
            "timestamps": data.timestamps,
            "labels": data.labels,
            "transactions": data.transactions,
            "metadata": data.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_berkeleydb_detection() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x62, 0x31];
        let metadata = WalletParser::identify_format(&data);
        assert_eq!(metadata.format, WalletFormat::BerkeleyDB);
    }

    #[test]
    fn test_entropy_calculation() {
        let uniform = vec![0xFF; 32];
        let entropy = WalletParser::calculate_entropy(&uniform);
        assert_eq!(entropy, 0.0);
    }
}
