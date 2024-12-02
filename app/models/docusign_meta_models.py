from pydantic import BaseModel

class UpdateConfigRequest(BaseModel):
    ds_client_id: str
    ds_api_account_id: str
    rsa_private_key: str
    rsa_public_key: str