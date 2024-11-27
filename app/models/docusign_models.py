from pydantic import BaseModel

class SignerInfo(BaseModel):
    signer_email: str
    signer_name: str

class WebHookInfo(BaseModel):
  event: str
  apiVersion: str
  uri: str
  retryCount: int
  configurationId: int
  generatedDateTime: str
  data: dict