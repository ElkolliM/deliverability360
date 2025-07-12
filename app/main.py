from fastapi import FastAPI, HTTPException, UploadFile, File
from app.utils.auth_checks import check_domain_auth
from app.models import AuthCheckResponse, DeliverabilityScoreResponse
import subprocess



app = FastAPI(title="Deliverability360 API", version="0.1")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/domain/check-auth", response_model=AuthCheckResponse)
async def domain_check_auth(domain: str):
    try:
        return check_domain_auth(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    

@app.post("/score", response_model=DeliverabilityScoreResponse)
async def score_deliverability(domain: str, file: UploadFile = File(...)):
    # Vérification domaine (SPF, DKIM, DMARC)
    auth_result = check_domain_auth(domain)

    # Lire contenu du .eml
    email_bytes = await file.read()

    # Analyse spam via spamc
    try:
        process = subprocess.Popen(
            ["spamc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(input=email_bytes)

        if process.returncode != 0:
            raise HTTPException(status_code=500, detail=f"SpamAssassin error: {stderr.decode()}")

        spam_output = stdout.decode()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running spamc: {str(e)}")

    # Extraire score depuis le header SpamAssassin
    import re
    match = re.search(r"X-Spam-Score: ([\d\.]+)", spam_output)
    spam_score = float(match.group(1)) if match else 0.0

    # Calcul du verdict
    verdict = "pass"
    if spam_score > 5 or auth_result["dkim"] != "found" or auth_result["spf"] != "pass":
        verdict = "warning"
    if spam_score > 7:
        verdict = "fail"

    # Suggestions simples
    recommendations = []
    if auth_result["dkim"] != "found":
        recommendations.append("Add DKIM record")
    if auth_result["spf"] != "pass":
        recommendations.append("Fix SPF record")
    if auth_result["dmarc"] != "present":
        recommendations.append("Add DMARC policy")
    if spam_score > 5:
        recommendations.append("Review email content")

    return DeliverabilityScoreResponse(
        domain=domain,
        spam_score=spam_score,
        auth=auth_result,
        verdict=verdict,
        recommendations=recommendations
    )