import base64
import os
from os import path

from typing import Annotated, Dict
from pydantic import BaseModel

from fastapi import APIRouter, HTTPException, File, UploadFile, Depends, status, Response, Cookie, Body, Request, Header
from fastapi.responses import JSONResponse
from config import settings
from auth.jwt_auth import get_access_token
from models.docusign_meta_models import UpdateConfigRequest
from models.auth import Token
from models.docusign_models import SignerInfo, WebHookInfo
from docusign_esign import ApiClient
from docusign_esign.apis import EnvelopesApi, TemplatesApi, UsersApi
from docusign_esign.models import EnvelopeDefinition, EnvelopeSummary, Document, Signer, SignHere, Tabs, Recipients, CarbonCopy, TemplateViewRequest, EnvelopeViewRequest
import xmltodict
import logging
import hmac
import hashlib
import base64

router = APIRouter()

# HMAC key from DocuSign Connect settings
CONNECT_KEY = 'your_connect_hmac_key'


class User(BaseModel):#TODO: Move this to the proper place
    id: str
    name: str
    email: str

# region GUIDE

# region ENDPOINTS


# Define the endpoint
@router.post("/update-config")
async def update_config(config: UpdateConfigRequest):
    try:
        # Update the .env file
        env_content = f"""DS_CLIENT_ID={config.ds_client_id}\nDS_API_ACCOUNT_ID={config.ds_api_account_id}"""
        with open(".env", "w") as env_file:
            env_file.write(env_content)

        # Update RSA private key
        with open("RSA_PRIVATE_KEY.pem", "w") as private_key_file:
            private_key_file.write(config.rsa_private_key)

        # Update RSA public key
        with open("RSA_PUBLIC_KEY.pem", "w") as public_key_file:
            public_key_file.write(config.rsa_public_key)

        url_scopes = "+".join(settings.scopes)

        consent_url = (
            f"https://{settings.authorization_server}/oauth/auth?response_type=code&"
            f"scope={url_scopes}&client_id={settings.ds_client_id}&redirect_uri={settings.redirect_uri}"
        )

        return {'consent':consent_url}

    except Exception as e:
        # Log the error appropriately
        print(f"Error updating configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the configuration.",
        )


@router.get("/grant-consent-url")
async def grant_consent_url():
    url_scopes = "+".join(settings.scopes)

    consent_url = (
        f"https://{settings.authorization_server}/oauth/auth?response_type=code&"
        f"scope={url_scopes}&client_id={settings.ds_client_id}&redirect_uri={settings.redirect_uri}"
    )

    return consent_url


@router.get("/login")
async def login(user_id: str, access_token: Annotated[Dict, Depends(get_access_token)], response: Response):
    content = {"message": "Login successful."}
    response = JSONResponse(content=content)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevent access via JavaScript
        secure=True,    # Send only over HTTPS
        samesite="none"  # Prevent cross-site requests
    )
    return response


@router.post("/send-test-envelope")
async def send_test_envelope(
    signer_info: SignerInfo = Body(...),
    access_token: str = Cookie(None),  # Read the token from an HTTP-only cookie
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Authentication token is missing.")
    
    try:
        # Create the envelope definition
        envelope = EnvelopeDefinition(email_subject="Test Envelope")

        # Read the demo document and encode it in Base64
        demo_docs_path = path.join(settings.demo_docs_path, "World_Wide_Corp_lorem.pdf")
        with open(demo_docs_path, "rb") as file:
            doc_pdf_bytes = file.read()
            doc_b64 = base64.b64encode(doc_pdf_bytes).decode("ascii")

        document_pdf = Document(  # Create the DocuSign document object
            document_base64=doc_b64,
            name="Lorem Ipsum",  # Can be different from the actual file name
            file_extension="pdf",  # Specify file extension
            document_id="1",  # Unique identifier for the document
        )

        envelope.documents = [document_pdf]

        # Create the signer recipient model
        signer = Signer(
            email=signer_info.signer_email,
            name=signer_info.signer_name,
            recipient_id="1",
            routing_order="1",
        )

        # Define the signing location
        sign_here = SignHere(
            anchor_string="**signature_1**",
            anchor_units="pixels",
            anchor_y_offset="10",
            anchor_x_offset="20",
        )

        cc1 = CarbonCopy(
            email=signer_info.signer_email, name=signer_info.signer_name, recipient_id="2", routing_order="2"
        )
        signer.tabs = Tabs(sign_here_tabs=[sign_here])

        # Assign recipients to the envelope
        recipients = Recipients(signers=[signer], carbon_copies=[cc1])
        envelope.recipients = recipients
        envelope.status = "sent"

        # Set up the API client
        api_client = ApiClient()
        api_client.host = settings.base_path
        api_client.set_default_header(
            header_name="Authorization", header_value=f"Bearer {access_token}"
        )

        # Send the envelope via the DocuSign API
        envelopes_api = EnvelopesApi(api_client)
        results: EnvelopeSummary = envelopes_api.create_envelope(
            account_id=settings.ds_api_account_id, envelope_definition=envelope
        )

        # Retrieve and return the envelope ID
        envelope_id = results.envelope_id
        return {"envelope_id": envelope_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/get-template-embed-url")
async def create_template(
    template_name: str = Body(...),
    base_document: UploadFile = File(...),
    access_token: str = Cookie(None),  # Read the token from an HTTP-only cookie
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Authentication token is missing.")

    try:
        # Read the uploaded document file and encode it in Base64
        file_content = await base_document.read()
        doc_b64 = base64.b64encode(file_content).decode("ascii")

        # Create the DocuSign document object
        document_pdf = Document(
            document_base64=doc_b64,
            name=template_name,  # Template name is used here for the document name
            file_extension=base_document.filename.split('.')[-1],  # Get file extension
            document_id="1",  # Unique identifier for the document
        )

        # Create an envelope definition for template creation
        envelope_definition = EnvelopeDefinition(
            email_subject="Template Creation Envelope",
            template_name=template_name,
        )
        envelope_definition.documents = [document_pdf]

        # Set up the recipient (Signer) for the template
        signer = Signer(
            email="signer@example.com",  # Example email, you should replace this
            name="Signer Name",
            recipient_id="1",
            routing_order="1",
        )

        sign_here = SignHere(
            anchor_string="**signature_1**",
            anchor_units="pixels",
            anchor_y_offset="10",
            anchor_x_offset="20",
        )

        signer.tabs = Tabs(sign_here_tabs=[sign_here])

        # Add recipient to the envelope
        recipients = Recipients(signers=[signer])
        envelope_definition.recipients = recipients
        envelope_definition.status = "created"  # Template status is set to 'created'

        # Set up the API client
        api_client = ApiClient()
        api_client.host = settings.base_path
        api_client.set_default_header(
            header_name="Authorization", header_value=f"Bearer {access_token}"
        )

        # Create the template using the DocuSign API
        templates_api = TemplatesApi(api_client)
        template_summary = templates_api.create_template(
            account_id=settings.ds_api_account_id, envelope_template=envelope_definition
        )

        # Retrieve and return the template's embed URL
        template_id = template_summary.template_id

        view_request = TemplateViewRequest(return_url=settings.redirect_uri)
        view_request.template_id = template_id

        # Construct the embed URL for the template
        embed_url = f"{settings.base_path}/app/templates/{template_id}/embed"

        results = templates_api.create_edit_view(
            account_id=settings.ds_api_account_id, template_view_request=view_request, template_id=template_id
        )

        url = results.url
        return {"embed_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@router.post("/get-envelope-embed-url")
async def create_envelope(
    envelope_name: str = Body(...),
    base_document: UploadFile = File(...),
    access_token: str = Cookie(None),  # Read the token from an HTTP-only cookie
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Authentication token is missing.")

    try:
        # Read the uploaded document file and encode it in Base64
        file_content = await base_document.read()
        doc_b64 = base64.b64encode(file_content).decode("ascii")

        # Create the DocuSign document object
        document_pdf = Document(
            document_base64=doc_b64,
            name=envelope_name,  # envelope name is used here for the document name
            file_extension=base_document.filename.split('.')[-1],  # Get file extension
            document_id="1",  # Unique identifier for the document
        )

        # Create an envelope definition for envelope creation
        envelope_definition = EnvelopeDefinition(
            email_subject="Envelope Creation Envelope",
            envelope_name=envelope_name,
        )
        envelope_definition.documents = [document_pdf]

        # Set up the recipient (Signer) for the envelope
        signer = Signer(
            email="signer@example.com",  # Example email, you should replace this
            name="Signer Name",
            recipient_id="1",
            routing_order="1",
        )

        sign_here = SignHere(
            anchor_string="**signature_1**",
            anchor_units="pixels",
            anchor_y_offset="10",
            anchor_x_offset="20",
        )

        signer.tabs = Tabs(sign_here_tabs=[sign_here])

        # Add recipient to the envelope
        recipients = Recipients(signers=[signer])
        envelope_definition.recipients = recipients
        envelope_definition.status = "created"  # Envelope status is set to 'created'

        # Set up the API client
        api_client = ApiClient()
        api_client.host = settings.base_path
        api_client.set_default_header(
            header_name="Authorization", header_value=f"Bearer {access_token}"
        )

        # Create the envelope using the DocuSign API
        envelopes_api = EnvelopesApi(api_client)
        envelope_summary = envelopes_api.create_envelope(
            account_id=settings.ds_api_account_id, envelope_definition=envelope_definition
        )

        # Retrieve and return the envelope's embed URL
        envelope_id = envelope_summary.envelope_id

        view_request = EnvelopeViewRequest(return_url=settings.redirect_uri)
        view_request.envelope_id = envelope_id

        # Construct the embed URL for the envelope
        embed_url = f"{settings.base_path}/app/envelopes/{envelope_id}/embed"

        results = envelopes_api.create_edit_view(
            account_id=settings.ds_api_account_id, envelope_view_request=view_request, envelope_id=envelope_id
        )

        url = results.url
        return {"embed_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users")
async def list_users(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Authentication token is missing.")
    try:
        # Set up the API client
        api_client = ApiClient()
        api_client.host = settings.base_path
        api_client.set_default_header(
            header_name="Authorization", header_value=f"Bearer {access_token}"
        )
        # Send the envelope via the DocuSign API
        users_api = UsersApi(api_client)
        response = users_api.list(settings.ds_api_account_id)

        # Assuming response.users is iterable
        users = [User(id=user.user_id, name=user.user_name, email=user.email) for user in response.users]
        
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/webhook/docusign")
async def docusign_webhook(webhook_info: WebHookInfo = Body(...)):
    try:
        print(webhook_info)
        return Response(status_code=200)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")