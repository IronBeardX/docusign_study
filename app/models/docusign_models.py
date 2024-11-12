from pydantic import BaseModel

class SignerInfo(BaseModel):
    signer_email: str
    signer_name: str