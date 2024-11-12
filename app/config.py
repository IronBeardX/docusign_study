from typing import AnyStr
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # DocuSign API credentials
    ds_client_id: str
    ds_api_account_id: str
    ds_private_key_file: str = "RSA_PRIVATE_KEY.pem"
    ds_public_key_file: str = "RSA_PUBLIC_KEY.pem"
    authorization_server: str = "account-d.docusign.com"
    base_path: str = "https://demo.docusign.net/restapi"
    demo_docs_path: str = "./app/static/demo_documents/"
    redirect_uri: str = "http://localhost:5173/setup/docusign"
    scopes: list = ["signature", "impersonation"]

    class Config:
        env_file = ".env"

settings = Settings()
