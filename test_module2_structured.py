from enum import Enum
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
import json

load_dotenv()
client = genai.Client()

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogAnalysis(BaseModel):
    summary: str = Field(description="One-sentence technical summary of the event")
    severity: SeverityLevel = Field(description="Severity level of the event: LOW, MEDIUM, HIGH, or CRITICAL")
    error_code: int = Field(description="Numeric error code extracted from the log entry")
    is_compromised: bool = Field(description="Whether the system or account is considered compromised based on the log")
    recommended_fix: list[str] = Field(description="List of recommended remediation actions to address the issue")

SYSTEM_PROMPT = """
You are a security information and event management (SIEM) log analyst. 

Your job is to analyze the provided server log entry and extract structured 
threat intelligence. 

Classify the severity accurately based on the nature of the event. Look for the following:

1. Security (breaches, exploits, risk indicators, unauthorized access.)
2. Secrets leak (API Keys, passwords, private information.) 

Example: unauthorized root access is CRITICAL.

Extract any numeric error codes present in the log. Determine whether the 
system or account is compromised. Provide concrete, actionable remediation 
steps as a list. The answer should respect the format for each issue spotted. 
Please create a separate response for each flaw detected.
"""

def parse_server_log(raw_log: str) -> list[LogAnalysis]:
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=f"Analyze the following raw server log:\n{raw_log}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=list[LogAnalysis],
        ),
    )
    # Validate and deserialize JSON string directly into the Pydantic object
    return [LogAnalysis.model_validate(item) for item in json.loads(response.text)]

if __name__ == "__main__":
    sample = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)\n"
        "2026-10-15 19:35:02 [ERROR] app[4471]: Failed to connect to database: connection string=postgresql://admin:P@ssw0rd!Sup3rS3cr3t@db.internal:5432/proddb (retries=3)"
    )
    for result in parse_server_log(sample):
        print(result.model_dump_json(indent=2))

# --- Automated Unit Test (Run with: pytest test_module2_structured.py) ---
def test_ssh_breach_log_parsing():
    sample_log = (
        "2026-10-15 02:11:44 [ALERT] sshd[9012]: Accepted password for root "
        "from 198.51.100.77 port 44122 ssh2 (ErrorCode=401 bypassed via PAM bug)"
        "2026-10-15 19:35:02 [ERROR] app[4471]: Failed to connect to database: connection string=postgresql://admin:P@ssw0rd!Sup3rS3cr3t@db.internal:5432/proddb (retries=3)"
    )
    result = parse_server_log(sample_log)

    assert result.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    assert result.error_code == 401
    assert result.is_compromised is True
    assert len(result.recommended_fix) >= 1
