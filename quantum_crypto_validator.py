#!/usr/bin/env python3
"""
Quantum Cryptography Transition Validator
Uses NLP rules to ensure complete migration from classical to quantum-safe crypto
"""

import re
import os
import sys
from pathlib import Path
from typing import List, Tuple, Dict
from dataclasses import dataclass

@dataclass
class ViolationReport:
    file_path: str
    line_number: int
    violation_type: str
    context: str
    suggestion: str

class QuantumCryptoValidator:
    """Validates codebase for quantum-safe cryptography compliance"""
    
    # Classical crypto patterns to detect
    CLASSICAL_CRYPTO_PATTERNS = {
        # Vulnerable signature schemes
        r'\bsr25519\b': "SR25519 is vulnerable to quantum attacks. Use SPHINCS+ or Lamport signatures.",
        r'\bed25519\b': "ED25519 is vulnerable to quantum attacks. Use SPHINCS+ or hash-based signatures.",
        r'\becdsa\b': "ECDSA is vulnerable to quantum attacks. Use SPHINCS+ or other PQC signatures.",
        r'\bsecp256[kr]1\b': "SECP256K1/R1 curves are quantum-vulnerable. Use quantum-safe alternatives.",
        
        # Vulnerable key exchange
        r'\bdiffie[\s-]*hellman\b': "Diffie-Hellman is quantum-vulnerable. Use QKD or post-quantum KEMs.",
        r'\becdh\b': "ECDH is quantum-vulnerable. Use QKD key exchange.",
        
        # Vulnerable hashes (for some use cases)
        r'\bsha2\b|\bsha256\b|\bsha512\b': "SHA2 may be weakened by quantum. Prefer SHA3 or SHAKE.",
        r'\bblake2\b': "Blake2 is not quantum-optimal. Use SHA3 for full quantum resistance.",
        r'\bkeccak256\b': "Raw Keccak256 - ensure using standardized SHA3-256 instead.",
        
        # Vulnerable random number generation
        r'\bgetrandom\b(?!.*quantum)': "System RNG may not be quantum. Use QKD/QRNG entropy.",
        r'\brand::thread_rng\b': "Thread RNG is not quantum. Use quantum entropy sources.",
        r'\bOsRng\b': "OS RNG may not be quantum. Prefer QKD-derived entropy.",
    }
    
    # Required quantum-safe patterns
    QUANTUM_SAFE_PATTERNS = {
        # Signatures
        r'\bsphincs\b': "SPHINCS+ hash-based signatures",
        r'\blamport\b': "Lamport one-time signatures",
        r'\bwinternitz\b': "Winternitz signatures",
        r'\bxmss\b': "XMSS stateful hash-based signatures",
        
        # Key exchange
        r'\bqkd\b': "Quantum Key Distribution",
        r'\bkyber\b': "Kyber post-quantum KEM",
        r'\bsaber\b': "SABER post-quantum KEM",
        
        # Hashing
        r'\bsha3\b': "SHA3 quantum-resistant hash",
        r'\bshake\b': "SHAKE extendable output function",
        
        # Entropy
        r'\bquantum_rng\b': "Quantum random number generator",
        r'\bqrng\b': "Quantum RNG",
        r'\bbeacon_entropy\b': "Beacon-derived quantum entropy",
    }
    
    # QKD-specific patterns we want to see
    QKD_PATTERNS = {
        r'\bdouble_ratchet\b': "Double ratchet for forward secrecy",
        r'\btonnetz\b': "Tonnetz harmonic filtering",
        r'\bfourier_transform\b|\bfft\b': "Fourier transform for beacon processing",
        r'\bhtm\b|hierarchical_temporal': "HTM for temporal pattern learning",
        r'\bqber\b': "Quantum Bit Error Rate monitoring",
        r'\bphoton_coherence\b': "Photon coherence metrics",
        r'\bquantum_gate\b': "Quantum gate operations",
    }
    
    def __init__(self, root_path: Path):
        self.root_path = root_path
        self.violations: List[ViolationReport] = []
        self.quantum_safe_files: List[str] = []
        self.files_scanned = 0
        
    def validate_file(self, file_path: Path) -> List[ViolationReport]:
        """Validate a single file for quantum crypto compliance"""
        violations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            # Check for classical crypto violations
            for pattern, message in self.CLASSICAL_CRYPTO_PATTERNS.items():
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check if it's in a comment
                        if not self._is_comment(line):
                            violations.append(ViolationReport(
                                file_path=str(file_path),
                                line_number=i,
                                violation_type="Classical Crypto",
                                context=line.strip(),
                                suggestion=message
                            ))
            
            # Check if file has any quantum-safe patterns
            has_quantum_crypto = False
            for pattern, desc in self.QUANTUM_SAFE_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    has_quantum_crypto = True
                    break
                    
            # Check for QKD-specific implementations
            qkd_score = 0
            for pattern, desc in self.QKD_PATTERNS.items():
                if re.search(pattern, content, re.IGNORECASE):
                    qkd_score += 1
                    
            # If file has crypto but no quantum-safe crypto, flag it
            if self._has_crypto_operations(content) and not has_quantum_crypto:
                violations.append(ViolationReport(
                    file_path=str(file_path),
                    line_number=0,
                    violation_type="Missing Quantum Crypto",
                    context="File contains cryptographic operations but no quantum-safe implementations",
                    suggestion="Add quantum-safe cryptographic primitives (SPHINCS+, SHA3, QKD, etc.)"
                ))
                
            # Bonus: suggest QKD enhancements
            if has_quantum_crypto and qkd_score < 2:
                violations.append(ViolationReport(
                    file_path=str(file_path),
                    line_number=0,
                    violation_type="QKD Enhancement Opportunity",
                    context="File could benefit from advanced QKD features",
                    suggestion="Consider adding: double ratchet, tonnetz filtering, HTM processing, or beacon entropy"
                ))
                
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
        return violations
    
    def _is_comment(self, line: str) -> bool:
        """Check if line is a comment"""
        stripped = line.strip()
        return stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*')
    
    def _has_crypto_operations(self, content: str) -> bool:
        """Check if file contains any cryptographic operations"""
        crypto_indicators = [
            r'\bsign\b', r'\bverify\b', r'\bhash\b', r'\bencrypt\b', 
            r'\bdecrypt\b', r'\bkey\b', r'\bcrypto\b', r'\brandom\b'
        ]
        for pattern in crypto_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def validate_directory(self, extensions: List[str] = None) -> Dict[str, any]:
        """Validate entire directory tree"""
        if extensions is None:
            extensions = ['.rs', '.py', '.js', '.ts', '.go', '.c', '.cpp', '.h']
            
        for root, dirs, files in os.walk(self.root_path):
            # Skip hidden directories and common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['target', 'node_modules', 'build']]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = Path(root) / file
                    self.files_scanned += 1
                    
                    violations = self.validate_file(file_path)
                    if violations:
                        self.violations.extend(violations)
                    else:
                        # Check if it's a quantum-safe file
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        for pattern in self.QUANTUM_SAFE_PATTERNS:
                            if re.search(pattern, content, re.IGNORECASE):
                                self.quantum_safe_files.append(str(file_path))
                                break
                                
        return self.generate_report()
    
    def generate_report(self) -> Dict[str, any]:
        """Generate validation report"""
        # Group violations by type
        violations_by_type = {}
        for v in self.violations:
            if v.violation_type not in violations_by_type:
                violations_by_type[v.violation_type] = []
            violations_by_type[v.violation_type].append(v)
            
        report = {
            "summary": {
                "files_scanned": self.files_scanned,
                "total_violations": len(self.violations),
                "quantum_safe_files": len(self.quantum_safe_files),
                "compliance_rate": (1 - len(self.violations) / max(self.files_scanned, 1)) * 100
            },
            "violations_by_type": {
                vtype: len(violations) for vtype, violations in violations_by_type.items()
            },
            "detailed_violations": violations_by_type,
            "quantum_safe_files": self.quantum_safe_files[:10],  # Top 10
            "recommendations": self._generate_recommendations(violations_by_type)
        }
        
        return report
    
    def _generate_recommendations(self, violations_by_type: Dict) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if "Classical Crypto" in violations_by_type:
            recommendations.append(
                "CRITICAL: Replace all classical cryptographic primitives with quantum-safe alternatives. "
                "Priority: sr25519→SPHINCS+, ed25519→Lamport, ECDSA→SPHINCS+, SHA2→SHA3"
            )
            
        if "Missing Quantum Crypto" in violations_by_type:
            recommendations.append(
                "IMPORTANT: Add quantum-safe cryptographic implementations to files handling sensitive operations. "
                "Consider using QKD for key exchange and QRNG for entropy."
            )
            
        if "QKD Enhancement Opportunity" in violations_by_type:
            recommendations.append(
                "ENHANCEMENT: Implement advanced QKD features like double ratchet with Lamport signatures, "
                "tonnetz harmonic filtering for beacon signals, and HTM for temporal pattern learning."
            )
            
        # Always recommend beacon signal integration
        recommendations.append(
            "INNOVATION: Integrate beacon signals from Toshiba QKD and Crypto4A QRNG devices. "
            "Use Fourier transforms to extract tonnetz harmonics and gate dissonant frequencies."
        )
        
        return recommendations
    
    def print_report(self, report: Dict):
        """Print formatted report"""
        print("\n" + "="*80)
        print("QUANTUM CRYPTOGRAPHY COMPLIANCE REPORT")
        print("="*80)
        
        print(f"\nSummary:")
        print(f"  Files Scanned: {report['summary']['files_scanned']}")
        print(f"  Total Violations: {report['summary']['total_violations']}")
        print(f"  Quantum-Safe Files: {report['summary']['quantum_safe_files']}")
        print(f"  Compliance Rate: {report['summary']['compliance_rate']:.1f}%")
        
        print(f"\nViolations by Type:")
        for vtype, count in report['violations_by_type'].items():
            print(f"  {vtype}: {count}")
            
        print(f"\nTop Violations:")
        for vtype, violations in report['detailed_violations'].items():
            print(f"\n  {vtype}:")
            for v in violations[:5]:  # Show top 5
                print(f"    {v.file_path}:{v.line_number}")
                print(f"      {v.context}")
                print(f"      → {v.suggestion}")
                
        print(f"\nExample Quantum-Safe Files:")
        for file in report['quantum_safe_files']:
            print(f"  ✓ {file}")
            
        print(f"\nRecommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")
            
        print("\n" + "="*80)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python quantum_crypto_validator.py <path_to_scan>")
        sys.exit(1)
        
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"Error: Path {path} does not exist")
        sys.exit(1)
        
    validator = QuantumCryptoValidator(path)
    report = validator.validate_directory()
    validator.print_report(report)
    
    # Exit with error code if violations found
    sys.exit(1 if report['summary']['total_violations'] > 0 else 0)


if __name__ == "__main__":
    main()