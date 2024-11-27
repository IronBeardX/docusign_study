from docusign_esign import ApiClient, ApiException
from docusign_esign.models import OauthAccess, UserInfo
from os import path
from typing import List
from config import settings

def get_access_token(user_id: str):
    try:
        api_client = ApiClient()
        api_client.set_oauth_host_name(settings.authorization_server)
        api_client.set_base_path(settings.authorization_server)

        private_key = (
            get_private_key(settings.ds_private_key_file)
            .encode("ascii")
            .decode("utf-8")
        )

        # Call request_jwt_user_token method
        token_response = get_jwt_token(
            private_key,
            settings.scopes,
            settings.ds_client_id,
            settings.authorization_server,
            user_id,
            api_client,
        )  # Admin user authorized in the app thats going to do interactions with docusign

        access_token = token_response.access_token

        return access_token
    
    except ApiException as e:
        return {'status_code': 500, 'detail': str(e)}

def get_jwt_token(private_key: str, scopes: List[str], client_id: str, auth_server: str, impersonated_user_id: str, api_client: ApiClient)-> OauthAccess:
    """Get the jwt token"""
    # api_client = ApiClient()
    response = api_client.request_jwt_user_token(
        client_id=client_id,
        user_id=impersonated_user_id,
        oauth_host_name=auth_server,
        private_key_bytes=private_key,
        expires_in=4000,
        scopes=scopes
    )#TODO: Can this authentication be done using request_jwt_application_token ?
    return response

def get_private_key(private_key_path: str) -> str:
    """
    Check that the private key present in the file and if it is, get it from the file.
    In the opposite way get it from config variable.
    """
    private_key_file = path.abspath(private_key_path)

    with open(private_key_file) as private_key_file:
        private_key = private_key_file.read()

    return private_key