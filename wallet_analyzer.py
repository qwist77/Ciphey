#!/usr/bin/env python3
"""
Cryptocurrency Wallet File Analyzer
Analyzes and extracts data from various wallet formats including Berkeley DB, SQLite, JSON, etc.
"""

import struct
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import Counter
import math

class WalletAnalyzer:
    """Main wallet analyzer class"""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.data = self.file_path.read_bytes()
        self.results = {
            'file_path': str(file_path),
            'file_size': len(self.data),
            'format': None,
            'addresses': [],
            'public_keys': [],
            'private_key_segments': [],
            'timestamps': [],
            'metadata': {},
            'labels': [],
            'transactions': [],
            'entropy_analysis': {}
        }
    
    def analyze(self) -> Dict:
        """Run complete analysis"""
        print("[*] Starting wallet analysis...")
        
        # Identify format
        self.identify_format()
        print(f"[+] Identified format: {self.results['format']}")
        
        # Extract data
        self.extract_addresses()
        print(f"[+] Found {len(self.results['addresses'])} addresses")
        
        self.extract_public_keys()
        print(f"[+] Found {len(self.results['public_keys'])} public keys")
        
        self.extract_timestamps()
        print(f"[+] Found {len(self.results['timestamps'])} timestamps")
        
        self.extract_encrypted_segments()
        print(f"[+] Found {len(self.results['private_key_segments'])} encrypted segments")
        
        self.extract_labels()
        print(f"[+] Found {len(self.results['labels'])} labels/metadata")
        
        self.analyze_entropy()
        print(f"[+] Entropy analysis complete")
        
        return self.results
    
    def identify_format(self):
        """Identify wallet file format"""
        if len(self.data) < 4:
            self.results['format'] = 'Unknown - file too small'
            return
        
        # Berkeley DB (b0, b1, b2, etc.)
        if len(self.data) > 5 and self.data[4] == 0x62 and 0x30 <= self.data[5] <= 0x39:
            self.results['format'] = f'Berkeley DB v{chr(self.data[5])}'
            self.results['metadata']['magic'] = self.data[4:6].hex()
            return
        
        # SQLite
        if self.data[:13] == b'SQLite format':
            self.results['format'] = 'SQLite'
            self.results['metadata']['magic'] = self.data[:16].hex()
            return
        
        # JSON
        if self.data[0:1] in (b'{', b'['):
            self.results['format'] = 'JSON'
            return
        
        # LevelDB
        if self.data[:4] == b'\xFF\x06\x00\x00':
            self.results['format'] = 'LevelDB'
            return
        
        self.results['format'] = 'Unknown Binary'
        self.results['metadata']['header'] = self.data[:32].hex()
    
    def extract_addresses(self):
        """Extract Bitcoin and Ethereum addresses"""
        addresses = set()
        
        # Bitcoin P2PKH pattern (76 a9 14 <20 bytes> 88 ac)
        for i in range(len(self.data) - 25):
            if (self.data[i] == 0x76 and self.data[i+1] == 0xa9 and 
                self.data[i+2] == 0x14):
                hash160 = self.data[i+3:i+23].hex()
                addresses.add(f"Bitcoin_P2PKH_{hash160[:16]}...")
        
        # Ethereum addresses (0x + 40 hex chars)
        for i in range(len(self.data) - 42):
            if self.data[i:i+2] == b'0x':
                try:
                    potential_addr = self.data[i:i+42].decode('ascii')
                    if all(c in '0123456789abcdefABCDEF' for c in potential_addr[2:]):
                        addresses.add(potential_addr)
                except:
                    pass
        
        # Legacy Bitcoin address patterns (look for common prefixes)
        for i in range(len(self.data) - 33):
            # P2SH pattern (a9 14 <20 bytes> 87)
            if self.data[i] == 0xa9 and self.data[i+1] == 0x14:
                hash160 = self.data[i+2:i+22].hex()
                addresses.add(f"Bitcoin_P2SH_{hash160[:16]}...")
        
        self.results['addresses'] = sorted(list(addresses))
    
    def extract_public_keys(self):
        """Extract public key patterns"""
        public_keys = set()
        
        # Compressed public keys (33 bytes: 02/03 + 32 bytes)
        for i in range(len(self.data) - 32):
            if self.data[i] in (0x02, 0x03):
                key = self.data[i:i+33].hex()
                public_keys.add(key)
        
        # Uncompressed public keys (65 bytes: 04 + 64 bytes)
        for i in range(len(self.data) - 64):
            if self.data[i] == 0x04:
                key = self.data[i:i+65].hex()
                public_keys.add(key)
        
        # Keep top 20 most frequent patterns
        self.results['public_keys'] = sorted(list(public_keys))[:20]
    
    def extract_timestamps(self):
        """Extract Unix timestamps (32-bit little-endian)"""
        timestamps = set()
        
        for i in range(0, len(self.data) - 3, 4):
            try:
                ts = struct.unpack('<I', self.data[i:i+4])[0]
                # Sanity check: valid Bitcoin era (2009-2100)
                if 1231006505 < ts < 4102444800:
                    timestamps.add(ts)
            except:
                pass
        
        # Also try 64-bit timestamps
        for i in range(0, len(self.data) - 7, 4):
            try:
                ts = struct.unpack('<Q', self.data[i:i+8])[0]
                if 1231006505 < ts < 4102444800:
                    timestamps.add(ts)
            except:
                pass
        
        self.results['timestamps'] = sorted(list(timestamps))
    
    def extract_encrypted_segments(self):
        """Extract high-entropy segments (likely encrypted data)"""
        segments = []
        threshold = 7.0  # Shannon entropy threshold
        
        window_size = 32
        for i in range(len(self.data) - window_size):
            window = self.data[i:i+window_size]
            entropy = self.calculate_entropy(window)
            
            if entropy > threshold:
                segments.append({
                    'offset': f'0x{i:x}',
                    'entropy': round(entropy, 2),
                    'preview': window[:8].hex() + '...'
                })
        
        # Keep top 20 highest entropy segments
        self.results['private_key_segments'] = sorted(
            segments, 
            key=lambda x: x['entropy'], 
            reverse=True
        )[:20]
    
    def extract_labels(self):
        """Extract human-readable labels and metadata"""
        labels = set()
        
        # Try to extract ASCII strings
        current_string = []
        for byte in self.data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 3:
                    s = ''.join(current_string)
                    if self.is_valid_label(s):
                        labels.add(s)
                current_string = []
        
        self.results['labels'] = sorted(list(labels))[:100]
    
    def analyze_entropy(self):
        """Analyze entropy of different file sections"""
        sections = {
            'header': self.data[:256],
            'middle': self.data[len(self.data)//2:len(self.data)//2 + 256],
            'tail': self.data[-256:] if len(self.data) >= 256 else self.data,
        }
        
        for name, section in sections.items():
            if section:
                entropy = self.calculate_entropy(section)
                self.results['entropy_analysis'][name] = round(entropy, 2)
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        freq = Counter(data)
        entropy = 0.0
        
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def is_valid_label(s: str) -> bool:
        """Check if string is a valid label"""
        if len(s) > 128:
            return False
        
        # Check if mostly alphanumeric with common separators
        valid_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.')
        return all(c in valid_chars or c.isspace() for c in s)
    
    def save_report(self, output_path: Optional[str] = None) -> str:
        """Save analysis report to JSON"""
        if output_path is None:
            output_path = str(self.file_path) + '_analysis.json'
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        return output_path
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*70)
        print("WALLET ANALYSIS SUMMARY")
        print("="*70)
        print(f"File: {self.results['file_path']}")
        print(f"Size: {self.results['file_size']} bytes")
        print(f"Format: {self.results['format']}")
        print("\n[+] FOUND DATA:")
        print(f"  • Addresses: {len(self.results['addresses'])}")
        print(f"  • Public Keys: {len(self.results['public_keys'])}")
        print(f"  • Encrypted Segments: {len(self.results['private_key_segments'])}")
        print(f"  • Timestamps: {len(self.results['timestamps'])}")
        print(f"  • Labels/Metadata: {len(self.results['labels'])}")
        
        if self.results['timestamps']:
            print(f"\n[+] TIMESTAMP RANGE:")
            import datetime
            min_ts = min(self.results['timestamps'])
            max_ts = max(self.results['timestamps'])
            print(f"  • Earliest: {datetime.datetime.fromtimestamp(min_ts)}")
            print(f"  • Latest: {datetime.datetime.fromtimestamp(max_ts)}")
        
        print(f"\n[+] ENTROPY ANALYSIS:")
        for section, entropy in self.results['entropy_analysis'].items():
            print(f"  • {section}: {entropy}")
        
        if self.results['addresses']:
            print(f"\n[+] SAMPLE ADDRESSES:")
            for addr in self.results['addresses'][:5]:
                print(f"  • {addr}")
        
        if self.results['labels']:
            print(f"\n[+] SAMPLE LABELS:")
            for label in self.results['labels'][:10]:
                print(f"  • {label}")
        
        print("\n" + "="*70)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python wallet_analyzer.py <wallet_file> [output_json]")
        sys.exit(1)
    
    wallet_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not Path(wallet_file).exists():
        print(f"Error: File not found: {wallet_file}")
        sys.exit(1)
    
    analyzer = WalletAnalyzer(wallet_file)
    analyzer.analyze()
    analyzer.print_summary()
    
    output = analyzer.save_report(output_file)
    print(f"\n[+] Full report saved to: {output}")


if __name__ == '__main__':
    main()
