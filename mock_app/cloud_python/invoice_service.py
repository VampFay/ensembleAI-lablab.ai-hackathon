from fastapi import FastAPI, HTTPException
import urllib.request
import urllib.parse
from pydantic import BaseModel

app = FastAPI()

class ReceiptRequest(BaseModel):
    receipt_url: str

@app.post("/api/v1/invoices/fetch_receipt")
def fetch_receipt(request: ReceiptRequest):
    """
    VULNERABILITY: Server-Side Request Forgery (SSRF)
    The application accepts a user-provided URL and fetches the content without
    validating if the URL points to internal services or cloud metadata endpoints.
    """
    target_url = request.receipt_url
    
    try:
        # VULNERABLE: No checks on target_url (e.g., blocking 169.254.169.254 or localhost)
        req = urllib.request.Request(target_url)
        with urllib.request.urlopen(req, timeout=3) as response:
            content = response.read().decode('utf-8')
            return {"status": "success", "content_preview": content[:200]}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch receipt: {str(e)}")

# To run locally for testing without uvicorn:
if __name__ == "__main__":
    print("Mock Cloud Python Invoice Service (SSRF Target)")
    print("In a real environment, this runs via uvicorn: uvicorn mock_app.cloud_python.invoice_service:app")
