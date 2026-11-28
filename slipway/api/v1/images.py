"""Public container images, read for the instance form."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from slipway.api.deps import require
from slipway.core.permissions import Perm
from slipway.schemas import ImageInfoOut
from slipway.services import registry
from slipway.services.auth import AuthContext

router = APIRouter(prefix="/images", tags=["images"])

Writer = Annotated[AuthContext, require(Perm.INSTANCES_WRITE)]


@router.get("/inspect")
async def inspect_image(ctx: Writer, ref: Annotated[str, Query(min_length=1, max_length=500)]) -> ImageInfoOut:
    """What a public image declares (its digest, exposed ports, volumes and default variables), so the form can
    suggest port and volume mappings. Read anonymously from the registry."""
    try:
        image = registry.parse(ref)
        info = await registry.inspect(image)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except registry.RegistryError as exc:
        code = status.HTTP_404_NOT_FOUND if exc.status_code in (401, 403, 404) else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(code, str(exc)) from exc
    return ImageInfoOut(**info.to_json())
