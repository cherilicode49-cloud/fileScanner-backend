import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.config import settings
from app.database import init_db
from app.services.yara_service import yara_service
from app.services.clamav_service import clamav_service
from app.api.routes import health, file_scan, zip_scan, url_scan, scan_history, scan_report

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("filescanner")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing FileScanner service...")

    # Ensure required directories exist
    settings.upload_path
    settings.temp_path
    settings.report_path
    settings.yara_rules_path
    settings.log_path

    # Initialize DB tables
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error("Database initialization failed: %s", e)

    # Check YARA rules
    yara_status = yara_service.get_status()
    if yara_status["available"]:
        logger.info("YARA rules initialized: %d rule files loaded", yara_status["loaded_files_count"])
    else:
        logger.warning("YARA rules not loaded: %s", yara_status.get("error"))

    # Check ClamAV Daemon
    clamav_ver = clamav_service.get_version()
    if clamav_ver["available"]:
        logger.info("ClamAV daemon reachable: %s", clamav_ver["version"])
    else:
        logger.warning("ClamAV daemon is currently offline at %s:%d - %s", settings.CLAMAV_HOST, settings.CLAMAV_PORT, clamav_ver.get("error"))

    yield

    # Shutdown actions
    logger.info("FileScanner service shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Locally hosted file, ZIP archive, and URL security scanning backend.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "data": None
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        errors.append(f"{loc}: {err.get('msg', 'validation error')}")
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "message": "Input validation error",
            "data": None,
            "errors": errors
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled server exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "An unexpected internal server error occurred",
            "data": None,
            "errors": [str(exc)] if settings.DEBUG else []
        }
    )


# Include API Routes
api_prefix = settings.API_V1_PREFIX
app.include_router(health.router, prefix=api_prefix)
app.include_router(file_scan.router, prefix=api_prefix)
app.include_router(zip_scan.router, prefix=api_prefix)
app.include_router(url_scan.router, prefix=api_prefix)
app.include_router(scan_history.router, prefix=api_prefix)
app.include_router(scan_report.router, prefix=api_prefix)


@app.get("/")
def root():
    return {
        "app": settings.APP_NAME,
        "status": "RUNNING",
        "documentation": "/docs"
    }

