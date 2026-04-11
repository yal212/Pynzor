from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from utils.http_client import HTTPClient, ClientConfig, Response


SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "description": "Enforces HTTPS connections",
        "risk": "high",
        "recommendation": "max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "description": "Prevents XSS and data injection",
        "risk": "high",
        "recommendation": "default-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking",
        "risk": "high",
        "recommendation": "DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME sniffing",
        "risk": "medium",
        "recommendation": "nosniff",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "XSS filter (legacy)",
        "risk": "low",
        "recommendation": "1; mode=block",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information",
        "risk": "medium",
        "recommendation": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser features",
        "risk": "low",
        "recommendation": "geolocation=(), microphone=()",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "description": "Isolates browsing context",
        "risk": "medium",
        "recommendation": "same-origin",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy",
        "description": "Controls cross-origin resources",
        "risk": "medium",
        "recommendation": "require-corp",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "description": "Prevents cross-origin loading",
        "risk": "medium",
        "recommendation": "same-origin",
    },
}


@dataclass
class HeaderAnalysis:
    header: str
    present: bool
    value: Optional[str]
    risk: str
    description: str
    recommendation: str


@dataclass
class HeaderResult:
    target: str
    start_time: datetime
    end_time: datetime
    analysis: list[HeaderAnalysis] = None  # type: ignore[assignment]
    score: int = 0
    grade: str = "F"
    missing_headers: list[str] = None  # type: ignore[assignment]


async def analyze_headers(
    target: str, http_client: HTTPClient | None = None
) -> HeaderResult:
    start_time = datetime.now()
    result = HeaderResult(
        target=target, start_time=start_time, end_time=start_time, missing_headers=[]
    )

    if http_client is None:
        config = ClientConfig()
        http_client = HTTPClient(config)
        should_close = True
    else:
        should_close = False

    analysis = []
    score = 100

    try:
        async with http_client:
            response = await http_client.get(target)

            if response.error:
                result.end_time = datetime.now()
                return result

            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            for header_key, info in SECURITY_HEADERS.items():
                header_analysis = HeaderAnalysis(
                    header=info["name"],
                    present=header_key in headers_lower,
                    value=headers_lower.get(header_key),
                    risk=info["risk"],
                    description=info["description"],
                    recommendation=info["recommendation"],
                )
                analysis.append(header_analysis)

                if not header_analysis.present:
                    if info["risk"] == "high":
                        score -= 20
                    elif info["risk"] == "medium":
                        score -= 10
                    else:
                        score -= 5
                    result.missing_headers.append(info["name"])

            score = max(0, score)

            if score >= 90:
                grade = "A"
            elif score >= 80:
                grade = "B"
            elif score >= 70:
                grade = "C"
            elif score >= 60:
                grade = "D"
            else:
                grade = "F"

            result = HeaderResult(
                target=target,
                start_time=start_time,
                end_time=datetime.now(),
                analysis=analysis,
                score=score,
                grade=grade,
                missing_headers=result.missing_headers,
            )
    finally:
        if should_close:
            await http_client.close()

    return result
