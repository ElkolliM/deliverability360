from pydantic import BaseModel

class AuthCheckResponse(BaseModel):
    domain: str
    spf: str
    dkim: str
    dmarc: str


class DeliverabilityScoreResponse(BaseModel):
    domain: str
    spam_score: float
    auth: AuthCheckResponse
    verdict: str
    recommendations: list[str]
