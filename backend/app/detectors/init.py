from .nxdomain import NXDomainDetector
from .tls_no_sni import TLSNoSNIDetector
from .beacon import BeaconDetector

def build_detectors():
    # Order doesn’t matter; each detector decides if it applies.
    return [
        NXDomainDetector(),
        TLSNoSNIDetector(),
        BeaconDetector(),
    ]
