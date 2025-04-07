from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from typing import Dict, Any, Optional
import datetime

class CertificateAnalyzer:
    """Analyzes and displays SSL certificate details."""
    @staticmethod
    def analyze_certificate(cert_der: bytes) -> Optional[Dict[str, Any]]:
        """Extracts details from a DER-encoded SSL certificate.
        
        Args:
            cert_der (bytes): The DER-encoded certificate.
        
        Returns:
            Optional[Dict[str, Any]]: Certificate details or None if analysis fails.
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            now = datetime.datetime.utcnow()
            validity = "valid" if cert.not_valid_before <= now <= cert.not_valid_after else "invalid"
            san = []
            for ext in cert.extensions:
                if ext.oid == x509.oid.NameOID.SUBJECT_ALTERNATIVE_NAME:
                    san = ext.value.get_values_for_type(x509.DNSName)
                    break
            return {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "validity": validity,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "sans": san,
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex()
            }
        except Exception as e:
            print(f"Certificate analysis failed: {e}")
            return None

    @staticmethod
    def print_certificate_info(cert_info: Dict[str, Any]) -> None:
        """Prints certificate details in a readable format.
        
        Args:
            cert_info (Dict[str, Any]): The certificate details to display.
        """
        print("Certificate Info:")
        print(f"  Subject: {cert_info['subject']}")
        print(f"  Issuer: {cert_info['issuer']}")
        print(f"  Validity: {cert_info['validity']}")
        print(f"  Valid From: {cert_info['not_valid_before']}")
        print(f"  Valid To: {cert_info['not_valid_after']}")
        print(f"  SANs: {', '.join(cert_info['sans']) or 'None'}")
        print(f"  SHA-256 Fingerprint: {cert_info['fingerprint']}")
