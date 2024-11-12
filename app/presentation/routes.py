import base64
import os
from os import path

from typing import Annotated, Dict

from fastapi import APIRouter, HTTPException, UploadFile, Depends, status, Response, Cookie, Body
from fastapi.responses import JSONResponse
from app.config import settings
from app.auth.jwt_auth import get_access_token
from app.models.docusign_meta_models import UpdateConfigRequest
from app.models.auth import Token
from app.models.docusign_models import SignerInfo
from docusign_esign import ApiClient
from docusign_esign.apis import EnvelopesApi
from docusign_esign.models import EnvelopeDefinition, EnvelopeSummary, Document, Signer, SignHere, Tabs, Recipients, CarbonCopy

router = APIRouter()

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


# region STUDY


# def create_envelope_draft(client, account_id):
#     envelope_api = EnvelopesApi(client)
#     # Create the signer recipient model
#     signer = Signer(
#         email="alejandroyeroval@gmail.com",
#         name="Alejandro Yero",
#         recipient_id="1",
#         routing_order="1",
#     )

#     cc1 = CarbonCopy(
#         email="alejandroyeroval@gmail.com",
#         name="Alejandro Yero",
#         recipient_id="2",
#         routing_order="2",
#     )

#     sign_here1 = SignHere(
#         anchor_string="**signature_1**",
#         anchor_units="pixels",
#         anchor_y_offset="10",
#         anchor_x_offset="20",
#     )

#     sign_here2 = SignHere(
#         anchor_string="/sn1/",
#         anchor_units="pixels",
#         anchor_y_offset="10",
#         anchor_x_offset="20",
#     )

#     signer.tabs = Tabs(sign_here_tabs=[sign_here1, sign_here2])
#     recipients = Recipients(signers=[signer], carbon_copies=[cc1])

#     with open(
#         path.join(settings.demo_docs_path, "World_Wide_Corp_lorem.pdf"), "rb"
#     ) as file:
#         doc_pdf_bytes = file.read()
#         doc_b64 = base64.b64encode(doc_pdf_bytes).decode("ascii")

#     document_pdf = Document(  # create the DocuSign document object
#         document_base64=doc_b64,
#         name="Lorem Ipsum",  # can be different from actual file name
#         file_extension="pdf",  # many different document types are accepted
#         document_id="1",  # a label used to reference the doc
#     )

#     envelope = EnvelopeDefinition(
#         email_subject="Please sign this document",
#         status="sent",
#         recipients=recipients,  # Add recipients
#         documents=[document_pdf],  # Add documents
#     )

#     try:
#         response = envelope_api.create_envelope(
#             account_id=account_id, envelope_definition=envelope
#         )
#         return response.envelope_id
#     except ApiException as e:
#         print(f"Error: {e}")


# def make_envelope(template_id, signer_email, signer_name):
#     """
#     Creates envelope
#     args -- parameters for the envelope:
#     signer_email, signer_name, signer_client_id
#     returns an envelope definition
#     """

#     # create the envelope definition
#     envelope_definition = EnvelopeDefinition(
#         status="sent",  # requests that the envelope be created and sent.
#         template_id=template_id,
#     )
#     # Create template role elements to connect the signer and cc recipients
#     # to the template
#     signer = TemplateRole(email=signer_email, name=signer_name, role_name="signer")
#     # Create a cc template role.
#     cc = TemplateRole(email=signer_email, name=signer_name, role_name="cc")

#     # Add the TemplateRole objects to the envelope object
#     envelope_definition.template_roles = [signer, cc]
#     return envelope_definition


# def make_template_req(doc_file, template_name):
#     """Creates template req object"""

#     # document 1 (pdf)
#     #
#     # The template has two recipient roles.
#     # recipient 1 - signer
#     # recipient 2 - cc
#     with open(doc_file, "rb") as file:
#         content_bytes = file.read()
#     base64_file_content = base64.b64encode(content_bytes).decode("ascii")

#     # Create the document model
#     document = Document(  # create the DocuSign document object
#         document_base64=base64_file_content,
#         name="Lorem Ipsum",  # can be different from actual file name
#         file_extension="pdf",  # many different document types are accepted
#         document_id=1,  # a label used to reference the doc
#     )

#     # Create the signer recipient model
#     signer = Signer(role_name="signer", recipient_id="1", routing_order="1")
#     # create a cc recipient to receive a copy of the envelope (transaction)
#     cc = CarbonCopy(role_name="cc", recipient_id="2", routing_order="2")
#     # Create fields using absolute positioning
#     # Create a sign_here tab (field on the document)
#     sign_here = SignHere(
#         document_id="1", page_number="1", x_position="191", y_position="148"
#     )
#     check1 = Checkbox(
#         document_id="1",
#         page_number="1",
#         x_position="75",
#         y_position="417",
#         tab_label="ckAuthorization",
#     )
#     check2 = Checkbox(
#         document_id="1",
#         page_number="1",
#         x_position="75",
#         y_position="447",
#         tab_label="ckAuthentication",
#     )
#     check3 = Checkbox(
#         document_id="1",
#         page_number="1",
#         x_position="75",
#         y_position="478",
#         tab_label="ckAgreement",
#     )
#     check4 = Checkbox(
#         document_id="1",
#         page_number="1",
#         x_position="75",
#         y_position="508",
#         tab_label="ckAcknowledgement",
#     )
#     list1 = List(
#         document_id="1",
#         page_number="1",
#         x_position="142",
#         y_position="291",
#         font="helvetica",
#         font_size="size14",
#         tab_label="list",
#         required="false",
#         list_items=[
#             ListItem(text="Red", value="red"),
#             ListItem(text="Orange", value="orange"),
#             ListItem(text="Yellow", value="yellow"),
#             ListItem(text="Green", value="green"),
#             ListItem(text="Blue", value="blue"),
#             ListItem(text="Indigo", value="indigo"),
#             ListItem(text="Violet", value="violet"),
#         ],
#     )
#     numerical = Numerical(
#         document_id="1",
#         validation_type="Currency",
#         page_number="1",
#         x_position="163",
#         y_position="260",
#         font="helvetica",
#         font_size="size14",
#         tab_label="numericalCurrency",
#         width="84",
#         height="23",
#         required="false",
#     )
#     radio_group = RadioGroup(
#         document_id="1",
#         group_name="radio1",
#         radios=[
#             Radio(
#                 page_number="1",
#                 x_position="142",
#                 y_position="384",
#                 value="white",
#                 required="false",
#             ),
#             Radio(
#                 page_number="1",
#                 x_position="74",
#                 y_position="384",
#                 value="red",
#                 required="false",
#             ),
#             Radio(
#                 page_number="1",
#                 x_position="220",
#                 y_position="384",
#                 value="blue",
#                 required="false",
#             ),
#         ],
#     )
#     text = Text(
#         document_id="1",
#         page_number="1",
#         x_position="153",
#         y_position="230",
#         font="helvetica",
#         font_size="size14",
#         tab_label="text",
#         height="23",
#         width="84",
#         required="false",
#     )
#     # Add the tabs model to the signer
#     # The Tabs object wants arrays of the different field/tab types
#     signer.tabs = Tabs(
#         sign_here_tabs=[sign_here],
#         checkbox_tabs=[check1, check2, check3, check4],
#         list_tabs=[list1],
#         numerical_tabs=[numerical],
#         radio_group_tabs=[radio_group],
#         text_tabs=[text],
#     )

#     # Top object:
#     template_request = EnvelopeTemplate(
#         documents=[document],
#         email_subject="Please sign this document",
#         recipients=Recipients(signers=[signer], carbon_copies=[cc]),
#         description="Example template created via the API",
#         name=template_name,
#         shared="false",
#         status="created",
#     )

#     return template_request


# def get_docusign_client(base_path: str, access_token: str):
#     api_client = ApiClient()
#     api_client.host = base_path
#     api_client.set_base_path(settings.authorization_server)
#     api_client.set_oauth_host_name(settings.authorization_server)

#     api_client.set_default_header(
#         header_name="Authorization", header_value=f"Bearer {access_token}"
#     )

#     return api_client


# def get_user_data(user_id: str = None):
#     if not user_id:
#         user_id = settings.ds_user_id

#     api_client = ApiClient()
#     api_client.set_base_path(settings.authorization_server)
#     api_client.set_oauth_host_name(settings.authorization_server)

#     private_key = (
#         get_private_key(settings.ds_private_key_file).encode("ascii").decode("utf-8")
#     )

#     # Call request_jwt_user_token method
#     token_response = get_jwt_token(
#         private_key,
#         settings.scopes,
#         settings.authorization_server,
#         settings.ds_client_id,
#         user_id,
#     )  # Admin user authorized in the app thats going to do interactions with docusign

#     access_token = token_response.access_token

#     # Save API account ID
#     user_info = api_client.get_user_info(access_token)
#     accounts = user_info.get_accounts()
#     api_account_id = accounts[0].account_id
#     base_path = accounts[0].base_uri + "/restapi"

#     return {
#         "access_token": access_token,
#         "api_account_id": api_account_id,
#         "base_path": base_path,
#     }


# region ENDPOINTS



# @router.post("/authenticate")
# async def authenticate():
#     try:
#         api_client = ApiClient()
#         # api_client.set_base_path(settings.authorization_server)
#         api_client.set_oauth_host_name(settings.authorization_server)

#         private_key = (
#             get_private_key(settings.ds_private_key_file)
#             .encode("ascii")
#             .decode("utf-8")
#         )

#         # Call request_jwt_user_token method
#         token_response = get_jwt_token(
#             private_key,
#             settings.scopes,
#             settings.authorization_server,
#             settings.ds_client_id,
#             settings.ds_user_id,
#             api_client,
#         )  # Admin user authorized in the app thats going to do interactions with docusign

#         access_token = token_response.access_token

#         # Save API account ID
#         user_info = api_client.get_user_info(access_token)
#         accounts = user_info.get_accounts()
#         api_account_id = accounts[0].account_id
#         base_path = accounts[0].base_uri + "/restapi"

#         return {
#             "access_token": access_token,
#             "api_account_id": api_account_id,
#             "base_path": base_path,
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @router.post("/envelope-status/{envlope_id}")
# async def get_envelope_status(envelope_id: str, base_path: str, access_token: str):

#     api_client = ApiClient()
#     api_client.host = base_path
#     api_client.set_default_header(
#         header_name="Authorization", header_value=f"Bearer {access_token}"
#     )

#     envelopes_api = EnvelopesApi(api_client)
#     returned_envelope: Envelope = envelopes_api.get_envelope(
#         settings.ds_api_account_id, envelope_id
#     )
#     return {"envelope_status": returned_envelope.status}


# @router.post("/ceate-template")
# async def create_template(
#     base_path: str, access_token: str, doc_file: str, template_name: str
# ) -> str:
#     api_client = ApiClient()
#     api_client.host = base_path
#     api_client.set_default_header(
#         header_name="Authorization", header_value=f"Bearer {access_token}"
#     )
#     templates_api = TemplatesApi(api_client)
#     template_req_object = make_template_req(doc_file, template_name)
#     template_summary: TemplateSummary = templates_api.create_template(
#         account_id=settings.ds_api_account_id, envelope_template=template_req_object
#     )
#     return template_summary.template_id


# @router.post("/send-envelope-from-template")
# async def send_envelope_from_template(
#     base_path: str,
#     access_token: str,
#     template_id: str,
#     signer_email: str,
#     signer_name: str,
# ):
#     """
#     1. Create the envelope request object
#     2. Send the envelope
#     """
#     # 1. Create the envelope request object
#     envelope_definition = make_envelope(template_id, signer_email, signer_name)

#     # 2. call Envelopes::create API method
#     # Exceptions will be caught by the calling function
#     api_client = ApiClient()
#     api_client.host = base_path
#     api_client.set_default_header(
#         header_name="Authorization", header_value=f"Bearer {access_token}"
#     )

#     envelope_api = EnvelopesApi(api_client)
#     results = envelope_api.create_envelope(
#         account_id=settings.ds_api_account_id, envelope_definition=envelope_definition
#     )
#     envelope_id = results.envelope_id
#     return {"envelope_id": envelope_id}


# @router.get("/create-elastic-template")
# async def create_elastic_template(
#     base_path: str,
#     access_token: str,
#     doc_pdf_path: str = "World_Wide_Corp_lorem.pdf",
# ):

#     api_client = ApiClient()
#     api_client.host = base_path
#     api_client.set_default_header(
#         header_name="Authorization", header_value=f"Bearer {access_token}"
#     )

#     # Create a display settings model
#     display_settings = DisplaySettings(
#         consent_button_text="I Agree",
#         display_name="Terms of Service",
#         downloadable=True,
#         format="modal",
#         must_read=True,
#         require_accept=True,
#         document_display="document",
#     )

#     # Read file from a local directory
#     # The reads could raise an exception if the file is not available!
#     with open(path.join(settings.demo_docs_path, doc_pdf_path), "rb") as file:
#         doc_docx_bytes = file.read()
#     doc_b64 = base64.b64encode(doc_docx_bytes).decode("ascii")
#     accounts_api = AccountsApi(api_client)
#     # response = accounts_api.create_clickwrap(
#     #     clickwrap_request=clickwrap_request,
#     #     account_id=settings.ds_api_account_id
#     # )


# @router.get("/envelope/embed-url")
# async def get_embed_url(base_path: str, access_token: str):
#     try:
#         api_client = ApiClient()
#         api_client.host = base_path
#         api_client.set_default_header(
#             header_name="Authorization", header_value=f"Bearer {access_token}"
#         )

#         envelope_id = create_envelope_draft(api_client, settings.ds_api_account_id)
#         view_request = ConsoleViewRequest(return_url=settings.redirect_uri)
#         # if args["starting_view"] == "envelope" and args["envelope_id"]:
#         view_request.envelope_id = envelope_id

#         # Step 2. Get the console view url
#         # Exceptions will be caught by the calling function

#         envelope_api = EnvelopesApi(api_client)
#         results = envelope_api.create_console_view(
#             account_id=settings.ds_api_account_id, console_view_request=view_request
#         )
#         url = results.url
#         return {"embedded_url": url}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
