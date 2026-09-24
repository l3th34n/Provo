
from pathlib import Path
from uuid import uuid4
import hashlib

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse

app = FastAPI(title="Provo API")

# Project directories
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(exist_ok=True)

# Allowed formats and maximum file size
ALLOWED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".webp",
    ".mp4", ".mov"
}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB


@app.get("/")
def homepage():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "online", "project": "Provo"}


@app.post("/api/upload")
async def upload_media(file: UploadFile = File(...)):

    original_name = Path(
        (file.filename or "").replace("\\", "/")
    ).name

    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format"
        )

    # Use a unique name to avoid overwriting other files
    file_id = uuid4().hex
    stored_name = file_id + extension
    destination = UPLOAD_DIR / stored_name

    size = 0
    sha256 = hashlib.sha256()

    try:
        with destination.open("wb") as output:

            # Read the upload in chunks
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)

                if size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 25 MB limit"
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

    # Send upload results back to the website
    return {
        "status": "uploaded",
        "file_id": file_id,
        "filename": original_name,
        "file_size": size,
        "sha256": sha256.hexdigest(),
        "verification_status": "not_checked"
    }