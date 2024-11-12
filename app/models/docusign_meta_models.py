from pydantic import BaseModel

# class Signer(BaseModel):
#     name: str
#     email: str
#     document: str  # Document base64 string

# class TemplateRequest(BaseModel):
#     template_name: str
#     document: str  # Base64 encoded document
#     fields: dict  # Custom fields for template creation

class UpdateConfigRequest(BaseModel):
    ds_client_id: str
    ds_api_account_id: str
    rsa_private_key: str
    rsa_public_key: str