import os
from dotenv import load_dotenv

load_dotenv()

class SecurityConfig:
    # VirusTotal API Key (Load from env)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Safe domains (Always trusted)
    TRUSTED_DOMAINS = [
        "google.com",
        "youtube.com",
        "stackoverflow.com",
        "github.com",
        "python.org",
        "pypi.org",
        "microsoft.com"
    ]
    
    # Cloud providers (Never fully trust root, unless specific subdomains)
    CLOUD_PROVIDERS = [
        "amazonaws.com",
        "googleapis.com",
        "vercel.app",
        "herokuapp.com",
        "azurewebsites.net",
        "blob.core.windows.net",
        "github.io"
    ]
    
    # Localhost (Treat as UNTRUSTED for testing/CTF challenges)
    UNTRUSTED_HOSTS = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0"
    ]
    
    # Security Thresholds
    VIRUSTOTAL_THRESHOLD = 0 # If > 0 engines flag it, it's dangerous
