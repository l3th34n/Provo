
from pathlib import Path
from uuid import uuid4
import hashlib
import logging

from fastapi import FastAPI, File, UploadFile, HTTPException, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from c2pa_checker import check_c2pa
from media_validation import EXTENSION_FORMATS, validate_media_header


# --------------------------------
# 1. INITIALIZE PROVO
# --------------------------------

app = FastAPI(title="Provo API", version="1.2.0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("provo")

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Serve the stylesheet and any future frontend assets referenced as
# /frontend/<name>. The homepage itself remains an explicit FileResponse.
app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR)), name="frontend")

ALLOWED_EXTENSIONS = set(EXTENSION_FORMATS)

MAX_FILE_SIZE = 25 * 1024 * 1024
UPLOAD_CHUNK_SIZE = 1024 * 1024


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


@app.get("/style.css", include_in_schema=False)
def frontend_stylesheet():
    """Serve the stylesheet while tolerating the common script.css filename."""
    css_file = next(
        (
            candidate
            for candidate in (
                FRONTEND_DIR / "style.css",
                FRONTEND_DIR / "script.css",
            )
            if candidate.is_file()
        ),
        None,
    )

    if css_file is None:
        raise HTTPException(
            status_code=404,
            detail="frontend/style.css or frontend/script.css not found"
        )

    return FileResponse(css_file, media_type="text/css")


# --------------------------------
# 4. HEALTH CHECK
# --------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "project": "Provo",
        "api_version": app.version,
        "pipeline_audit_version": "1.0",
        "c2pa": "available",
        "max_upload_bytes": MAX_FILE_SIZE,
        "supported_extensions": sorted(ALLOWED_EXTENSIONS),
    }


# --------------------------------
# 5. FILE UPLOAD AND VERIFICATION
# --------------------------------

@app.post("/api/upload")
async def upload_media(response: Response, file: UploadFile = File(...)):

    response.headers["Cache-Control"] = "no-store"

    # Extract a safe filename
    original_name = Path(
        (file.filename or "").replace("\\", "/")
    ).name

    if not original_name:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="A filename is required"
        )

    extension = Path(original_name).suffix.lower()

    # Check file extension
    if extension not in ALLOWED_EXTENSIONS:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format"
        )

    # Generate a unique temporary storage name
    file_id = uuid4().hex
    stored_name = file_id + extension
    destination = UPLOAD_DIR / stored_name

    size = 0
    sha256 = hashlib.sha256()
    detected_format = None

    # Validate and save the upload without loading the whole asset into memory.
    try:
        first_chunk = await file.read(UPLOAD_CHUNK_SIZE)

        if not first_chunk:
            raise HTTPException(
                status_code=400,
                detail="Cannot upload an empty file"
            )

        try:
            detected_format = validate_media_header(original_name, first_chunk)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        with destination.open("wb") as output:
            output.write(first_chunk)
            size = len(first_chunk)
            sha256.update(first_chunk)

            while True:
                chunk = await file.read(UPLOAD_CHUNK_SIZE)

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

    except Exception:
        destination.unlink(missing_ok=True)
        raise

    finally:
        await file.close()

    # The native C2PA reader is synchronous, so run it outside the async loop.
    # Uploaded media is removed immediately after inspection; file_id remains a
    # request correlation identifier and no user media is retained by default.
    try:
        c2pa_result = await run_in_threadpool(check_c2pa, destination)
    finally:
        destination.unlink(missing_ok=True)

    # Return results to the frontend
    return {
        "status": "uploaded",
        "file_id": file_id,
        "filename": original_name,
        "file_size": size,
        "media_format": detected_format,
        "file_retained": False,
        "sha256": sha256.hexdigest(),
        "verification_status": c2pa_result["status"],
        "c2pa": c2pa_result
    }
