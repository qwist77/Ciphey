/// Wallet decoder module for Ciphey
/// Integrates wallet analysis into the decoding pipeline
use super::interface::{Decoder, DecodeResult};
use std::collections::HashMap;

pub struct WalletDecoder;

impl Decoder for WalletDecoder {
    fn decode(&self, input: &str) -> DecodeResult {
        // This decoder is for analyzing wallet files
        // It works on file paths, not direct text input
        
        DecodeResult {
            success: false,
            output: None,
            confidence: 0.0,
        }
    }

    fn get_name(&self) -> &'static str {
        "wallet_analyzer"
    }
}

/// Utility functions for wallet analysis
pub mod utils {
    use std::path::Path;
    use std::fs;

    pub fn analyze_wallet_file(path: &str) -> Result<super::super::wallet_parser::ExtractedWalletData, String> {
        let data = fs::read(path)
            .map_err(|e| format!("Failed to read wallet file: {}", e))?;
        
        super::super::wallet_parser::WalletParser::parse_berkeleydb(&data)
    }

    pub fn is_wallet_file(path: &str) -> bool {
        if let Ok(data) = fs::read(path) {
            matches!(
                super::super::wallet_parser::WalletParser::identify_format(&data).format,
                super::super::wallet_parser::WalletFormat::BerkeleyDB
                    | super::super::wallet_parser::WalletFormat::SQLite
                    | super::super::wallet_parser::WalletFormat::JSON
                    | super::super::wallet_parser::WalletFormat::LevelDB
            )
        } else {
            false
        }
    }
}
