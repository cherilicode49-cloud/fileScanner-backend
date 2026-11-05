from typing import Any, Optional
from fastapi.responses import JSONResponse


def success_response(data: Any = None, message: str = "Success", status_code: int = 200) -> JSONResponse:
    """Standard success API response."""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": True,
            "message": message,
            "data": data
        }
    )


def error_response(
    message: str = "An error occurred",
    data: Any = None,
    errors: Optional[list] = None,
    status_code: int = 400
) -> JSONResponse:
    """Standard error API response."""
    content = {
        "success": False,
        "message": message,
        "data": data,
    }
    if errors is not None:
        content["errors"] = errors
    return JSONResponse(status_code=status_code, content=content)

