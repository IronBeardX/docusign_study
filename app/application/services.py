from docusign_esign import EnvelopesApi, ApiException
from auth.jwt_auth import get_docusign_client

# Start a new signing process
def start_signing_process():
    api_client, access_token = get_docusign_client()
    envelopes_api = EnvelopesApi(api_client)

    # Example of sending a document for signing
    envelope_definition = {
        # Populate with required envelope data like signers, documents, etc.
    }

    try:
        envelope = envelopes_api.create_envelope("account_id", envelope_definition)
        return envelope.envelope_id
    except ApiException as e:
        raise Exception(f"DocuSign API error: {e}")

# Check the status of a signing process
def check_signing_status(envelope_id: str):
    api_client, access_token = get_docusign_client()
    envelopes_api = EnvelopesApi(api_client)
    try:
        status = envelopes_api.get_envelope("account_id", envelope_id)
        return status
    except ApiException as e:
        raise Exception(f"Error fetching envelope status: {e}")
