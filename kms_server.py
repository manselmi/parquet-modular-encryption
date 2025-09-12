#!/usr/bin/env python
# vim: set ft=python :

from __future__ import annotations

import base64
import binascii
from enum import Enum
from typing import Annotated, Any, Literal

import uvicorn
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap
from fastapi import status
from fastapi.applications import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.params import Path, Security
from fastapi.routing import APIRouter
from fastapi.security import APIKeyHeader
from pydantic.config import ConfigDict
from pydantic.fields import Field, PrivateAttr
from pydantic.functional_validators import model_validator
from pydantic.main import BaseModel

KEY_WRAPPING_TAG = "Key wrapping"


# Hardcoded for demo purposes only! Never do this IRL!
class WrappingKey(Enum):
    PUBLIC = bytes.fromhex("960f87a5e2eb7d07e67892cbdd60d94053d43f3c26e2bca1c52a6efd3572b8d0")
    INTERNAL = bytes.fromhex("fb0d234a0b650ca3382bb7f481db2f96c7bccaf66f99b9160811c1cacb3f616d")
    CONFIDENTIAL = bytes.fromhex("efdbe2afc153a13dae44b7415c4ef0d08cc1eaec75f5029220ec738141090bf2")
    RESTRICTED = bytes.fromhex("ab4ae72b44fc91c8c2b5e559855a5eded40595ce423cde6b6435e2821da72c44")


WrappingKeyIdLiteral = Literal[
    WrappingKey.PUBLIC.name,
    WrappingKey.INTERNAL.name,
    WrappingKey.CONFIDENTIAL.name,
    WrappingKey.RESTRICTED.name,
]
WrappingKeyIdPath = Annotated[WrappingKeyIdLiteral, Path(title="wrapping key ID")]


class Model(BaseModel):
    model_config = ConfigDict(
        allow_inf_nan=False,
        extra="forbid",
        strict=True,
    )


class WrapRequestBody(Model):
    key: str = Field(...)
    _decoded_key: bytes = PrivateAttr()

    @model_validator(mode="after")
    def decode_key(self) -> WrapRequestBody:
        decoded_key = _decode_key(self.key)

        if len(decoded_key) < 16:
            raise ValueError("key size must be at least 16 bytes")

        self._decoded_key = decoded_key
        return self


class UnwrapRequestBody(Model):
    key: str = Field(...)
    _decoded_key: bytes = PrivateAttr()

    @model_validator(mode="after")
    def decode_key(self) -> UnwrapRequestBody:
        decoded_key = _decode_key(self.key)

        if len(decoded_key) < 24:
            raise ValueError("key size must be at least 24 bytes")

        self._decoded_key = decoded_key
        return self


class ResponseBody(Model):
    key: str = None
    decoded_key: bytes = Field(..., exclude=True)

    @model_validator(mode="after")
    def encode_key(self) -> ResponseBody:
        self.key = base64.b64encode(self.decoded_key).decode()
        return self


def _decode_key(key: str) -> bytes:
    try:
        decoded_key = base64.b64decode(key, validate=True)
    except binascii.Error as exc:
        raise ValueError(str(exc)) from exc

    if len(decoded_key) % 8 != 0:
        raise ValueError("key length must be a multiple of 8 bytes")

    return decoded_key


async def unwrap_authz(wrapping_key_id: WrappingKeyIdPath, api_key: str | None) -> None:
    if (
        wrapping_key_id == WrappingKey.PUBLIC.name
        or (
            wrapping_key_id == WrappingKey.INTERNAL.name
            and api_key
            in {
                WrappingKey.INTERNAL.name,
                WrappingKey.CONFIDENTIAL.name,
                WrappingKey.RESTRICTED.name,
            }
        )
        or (
            wrapping_key_id == WrappingKey.CONFIDENTIAL.name
            and api_key in {WrappingKey.CONFIDENTIAL.name, WrappingKey.RESTRICTED.name}
        )
        or (
            wrapping_key_id == WrappingKey.RESTRICTED.name
            and api_key == WrappingKey.RESTRICTED.name
        )
    ):
        return

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)


app = FastAPI(swagger_ui_parameters={"defaultModelsExpandDepth": -1})
router = APIRouter(prefix="/api/v1")
header_scheme = APIKeyHeader(name="x-api-key", auto_error=False)


@router.post("/wrap/{wrapping_key_id}", response_model=ResponseBody, tags=[KEY_WRAPPING_TAG])
async def wrap_key(wrapping_key_id: WrappingKeyIdPath, wrap_request_body: WrapRequestBody) -> Any:
    wrapping_key = WrappingKey[wrapping_key_id].value
    wrapped_key = aes_key_wrap(wrapping_key, wrap_request_body._decoded_key)
    return ResponseBody(decoded_key=wrapped_key)


@router.post("/unwrap/{wrapping_key_id}", response_model=ResponseBody, tags=[KEY_WRAPPING_TAG])
async def unwrap_key(
    wrapping_key_id: WrappingKeyIdPath,
    unwrap_request_body: UnwrapRequestBody,
    api_key: str | None = Security(header_scheme),
) -> Any:
    await unwrap_authz(wrapping_key_id, api_key)
    wrapping_key = WrappingKey[wrapping_key_id].value
    try:
        unwrapped_key = aes_key_unwrap(wrapping_key, unwrap_request_body._decoded_key)
    except InvalidUnwrap as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return ResponseBody(decoded_key=unwrapped_key)


app.include_router(router)


if __name__ == "__main__":
    uvicorn.run(
        "kms_server:app",
        port=8001,
        reload=True,
    )
