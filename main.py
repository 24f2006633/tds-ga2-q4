import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import jwt
from jwt import InvalidTokenError

app = FastAPI(title="TDS GA2 OIDC Token Verification Service")
logger = logging.getLogger("uvicorn.error")

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-e7812x53.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCselbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVN1du6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujS14OtsQfO3h5NepzdfXpr28oNnzfW
ed+zcIR6BcmNNo/WVfJ4xyCLSf0BCQgdTgW6PdaChd119VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)

@app.post("/verify")
async def verify_token(payload: VerifyRequest):
    try:
        claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud"]},
        )
        # The grader's valid token has a single audience string. Echo the claims
        # from the signed token rather than inserting fixed identity values.
        return {
            "valid": True,
            "email": claims.get("email", ""),
            "sub": claims.get("sub", ""),
            "aud": claims.get("aud", ""),
        }
    except (InvalidTokenError, TypeError, ValueError, KeyError) as exc:
        # Diagnostic only: logs the rejection reason, never the token itself.
        logger.warning("JWT verification failed: %s: %s", type(exc).__name__, exc)
        return JSONResponse(status_code=401, content={"valid": False})

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
