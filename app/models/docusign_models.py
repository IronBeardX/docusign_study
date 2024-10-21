# app/models/docusign_models.py
from pydantic import BaseModel

class Signer(BaseModel):
    name: str
    email: str
    document: str  # Document base64 string

class TemplateRequest(BaseModel):
    template_name: str
    document: str  # Base64 encoded document
    fields: dict  # Custom fields for template creation
