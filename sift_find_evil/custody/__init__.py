"""Chain-of-custody primitives: cryptographic finding receipts.

Binds each finding to a signed envelope carrying the evidence-image SHA-256 and
tool provenance, so a hallucinated finding (one the engine never produced) has
no valid receipt. See ``receipt`` for the minting/verification API.
"""

from .receipt import ReceiptMinter, mint_receipt, verify_receipt

__all__ = ["ReceiptMinter", "mint_receipt", "verify_receipt"]
