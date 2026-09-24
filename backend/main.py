
from pathlib import Path
from uuid import uuid4
import hashlib
import logging

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse

from c2pa_checker import check_c2pa


# --------------------------------
# 1. INITIALIZE PROVO
# --------------------------------

app = FastAPI(title="Provo API", version="1.0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("provo")

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".webp",
    ".mp4", ".mov"
}

MAX_FILE_SIZE = 25 * 1024 * 1024


# --------------------------------
# 3. WEBSITE HOMEPAGE
# --------------------------------

@app.get("/")
def homepage():
    html_file = FRONTEND_DIR / "index.html"

    if not html_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="frontend/index.html not found"
        )

    return FileResponse(html_file)


# --------------------------------
# 4. HEALTH CHECK
# --------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "project": "Provo",
        "c2pa": "installed"
    }


# --------------------------------
# 5. FILE UPLOAD AND VERIFICATION
# --------------------------------

@app.post("/api/upload")
async def upload_media(file: UploadFile = File(...)):

    # Extract a safe filename
    original_name = Path(
        (file.filename or "").replace("\\", "/")
    ).name

    extension = Path(original_name).suffix.lower()

    # Check file extension
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format"
        )

    # Generate a unique storage name
    file_id = uuid4().hex
    stored_name = file_id + extension
    destination = UPLOAD_DIR / stored_name

    size = 0
    sha256 = hashlib.sha256()

    # Save the uploaded file
    try:
        with destination.open("wb") as output:

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                size += len(chunk)

                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds 25 MB"
                    )

                output.write(chunk)
                sha256.update(chunk)

        if size == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot upload an empty file"
            )

    except Exception:
        destination.unlink(missing_ok=True)
        raise

    finally:
        await file.close()

    # Inspect the saved media
    c2pa_result = check_c2pa(destination)

    # Return results to the frontend
    return {
        "status": "uploaded",
        "file_id": file_id,
        "filename": original_name,
        "file_size": size,
        "sha256": sha256.hexdigest(),
        "verification_status": c2pa_result["status"],
        "c2pa": c2pa_result
    }
