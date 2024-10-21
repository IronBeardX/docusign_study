from typing import Annotated
from fastapi import APIRouter, HTTPException, Depends
from docusign_esign import ApiClient
from docusign_esign import TemplatesApi, EnvelopeTemplate, Signer, SignHere, Recipients, Document
# from docusign_esign.models import 
from app.config import settings
from app.auth.jwt_auth import get_private_key, get_jwt_token

router = APIRouter()

def get_docusign_client(base_path: str, access_token: str) -> ApiClient:
    api_client = ApiClient()
    api_client.host = base_path
    api_client.set_base_path(settings.authorization_server)
    api_client.set_oauth_host_name(settings.authorization_server)

    api_client.set_default_header(header_name="Authorization", header_value=f'Bearer {access_token}')

    return api_client

def get_user_data(user_id: str = None):
    if not user_id:
        user_id = settings.ds_user_id

    api_client = ApiClient()
    api_client.set_base_path(settings.authorization_server)
    api_client.set_oauth_host_name(settings.authorization_server)

    private_key = get_private_key(settings.ds_private_key_file).encode("ascii").decode("utf-8")

    # Call request_jwt_user_token method
    token_response = get_jwt_token(private_key, settings.scopes, settings.authorization_server, settings.ds_client_id,
                                user_id)# Admin user authorized in the app thats going to do interactions with docusign

    access_token = token_response.access_token

    # Save API account ID
    user_info = api_client.get_user_info(access_token)
    accounts = user_info.get_accounts()
    api_account_id = accounts[0].account_id
    base_path = accounts[0].base_uri + "/restapi"

    return {"access_token": access_token, "api_account_id": api_account_id, "base_path": base_path}

@router.get("/grant-consent-url")
async def grant_consent_url():
    url_scopes = "+".join(settings.scopes)

    consent_url = f"https://{settings.authorization_server}/oauth/auth?response_type=code&" \
                  f"scope={url_scopes}&client_id={settings.ds_client_id}&redirect_uri={settings.redirect_uri}"

    return consent_url

@router.post("/authenticate")
async def authenticate():
    try:
        api_client = ApiClient()
        # api_client.set_base_path(settings.authorization_server)
        api_client.set_oauth_host_name(settings.authorization_server)

        private_key = get_private_key(settings.ds_private_key_file).encode("ascii").decode("utf-8")

        # Call request_jwt_user_token method
        token_response = get_jwt_token(private_key, settings.scopes, settings.authorization_server, settings.ds_client_id,
                                    settings.ds_user_id, api_client)# Admin user authorized in the app thats going to do interactions with docusign

        access_token = token_response.access_token

        # Save API account ID
        user_info = api_client.get_user_info(access_token)
        accounts = user_info.get_accounts()
        api_account_id = accounts[0].account_id
        base_path = accounts[0].base_uri + "/restapi"

        return {"access_token": access_token, "api_account_id": api_account_id, "base_path": base_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/template-preview")
async def template_preview(user_data: Annotated[dict, Depends(get_user_data)]):
    # template-id: 2c732d93-88b2-4511-b7c9-07eb53ba14c3
    client_api = get_docusign_client(user_data['base_path'], user_data['access_token'])
    print(user_data)
    templates_api = TemplatesApi(client_api)
    html_preview = templates_api.create_template_responsive_html_preview(
        user_data['api_account_id'],
        "2c732d93-88b2-4511-b7c9-07eb53ba14c3"
        )
    return html_preview


@router.post("/create-template")
async def create_template(
    user_data: Annotated[dict, Depends(get_user_data)]):
    try:
        base_path = user_data['base_path']
        access_token = user_data['access_token']

        # Initialize DocuSign API client
        api_client = get_docusign_client(base_path, access_token)

        # Create an instance of the Templates API
        templates_api = TemplatesApi(api_client)



        # Define the document to be used in the template (as a base64-encoded string)
        document_base64 = "..."  # You should load and base64 encode the document here

        # Create the document object
        document = Document(
            document_base64=document_base64,
            name="Sample Document",  # Name of the document
            file_extension="pdf",
            document_id="1"
        )

        # Define signer roles (recipients)
        signer = Signer(
            role_name="Signer",  # Name of the role
            recipient_id="1",
            routing_order="1"
        )

        # Define a signature tab for the signer (location on the document to sign)
        sign_here = SignHere(
            document_id="1",
            page_number="1",
            recipient_id="1",
            tab_label="SignHere",
            x_position="200",
            y_position="200"
        )

        # Add the tab to the signer
        signer.tabs = {"sign_here_tabs": [sign_here]}

        # Create the recipients object and assign the signer
        recipients = Recipients(
            signers=[signer]
        )

        # Define the envelope template
        envelope_template = EnvelopeTemplate(
            description="Sample template created via API",
            name="Sample Template",
            shared="false",  # Specify whether the template is shared
            documents=[document],
            recipients=recipients
        )

        # Use the Templates API to create the template
        # template_definition = TemplateDefinition(
        #     template_id=None,
        #     name="My Sample Template",
        # )

        created_template = templates_api.create_template(settings.ds_user_id)

        return {"template_id": created_template.template_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating template: {str(e)}")

@router.get("/create-envelope")
async def create_envelope():
    pass

@router.get("/send-envelope")
async def send_envelope():
    pass

@router.get("/check_envelope_status")
async def check_envelope_status():
    pass