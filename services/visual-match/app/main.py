"""XGenGuardian — visual-match service.

Two endpoints:
  POST /embed  {image_url | image_b64}     -> 512-dim CLIP embedding
  POST /match  {image_url | image_b64}     -> top-k brand matches via pgvector

Loads OpenCLIP ViT-B/32 at boot. CPU-only works; GPU is faster.
Favicon path uses pHash + MMH3 for exact-match lookups in brands.favicon_hashes.
"""

from __future__ import annotations

import base64
import io
import os
from contextlib import asynccontextmanager
from typing import Any

import httpx
import imagehash
import mmh3
import open_clip
import psycopg
import torch
from fastapi import FastAPI, HTTPException
from PIL import Image
from psycopg.rows import dict_row
from pydantic import BaseModel

PG_DSN = os.getenv("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MODEL_NAME = os.getenv("CLIP_MODEL", "ViT-B-32")
PRETRAINED = os.getenv("CLIP_PRETRAINED", "openai")

_model = None
_preprocess = None
_pg: psycopg.Connection | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _model, _preprocess, _pg
    model, _, preprocess = open_clip.create_model_and_transforms(
        MODEL_NAME, pretrained=PRETRAINED, device=DEVICE
    )
    model.train(False)  # equivalent to .eval(); set inference mode
    _model = model
    _preprocess = preprocess
    _pg = psycopg.connect(PG_DSN, autocommit=True, row_factory=dict_row)
    yield
    if _pg:
        _pg.close()


app = FastAPI(title="xgg-visual-match", lifespan=lifespan)


class EmbedRequest(BaseModel):
    image_url: str | None = None
    image_b64: str | None = None


class EmbedResponse(BaseModel):
    vector: list[float]


class MatchResponse(BaseModel):
    top: list[dict[str, Any]]
    favicon_match: dict[str, Any] | None = None
    # Perceptual hashes of the *input* image — useful for analyst drill-down
    # and for the deny-cache pre-filter when brand_screenshots.phash/dhash
    # are populated (migration 0006). Hamming distance threshold is the
    # caller's choice; we expose the raw 16-char hex.
    phash: str | None = None
    dhash: str | None = None
    # If brand_screenshots.phash is populated, closest Hamming-distance match.
    phash_match: dict[str, Any] | None = None


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "device": DEVICE, "model": MODEL_NAME}


@app.post("/embed", response_model=EmbedResponse)
async def embed_image(req: EmbedRequest) -> EmbedResponse:
    img = await _load_image(req)
    vec = _clip_embed(img)
    return EmbedResponse(vector=vec.tolist())


@app.post("/match", response_model=MatchResponse)
async def match_image(req: EmbedRequest) -> MatchResponse:
    if _pg is None:
        raise HTTPException(503, "pg not ready")
    img = await _load_image(req)
    vec = _clip_embed(img)
    favicon = None

    # Perceptual hashes on the full image. Computed always; cheap (a few ms)
    # and useful for analyst drill-down even when no brand pHash is stored.
    in_phash = imagehash.phash(img)
    in_dhash = imagehash.dhash(img)
    phash_str = str(in_phash)
    dhash_str = str(in_dhash)

    # CLIP similarity search in pgvector
    with _pg.cursor() as cur:
        cur.execute(
            """
            SELECT b.brand_name, bs.page_label,
                   1 - (bs.embedding <=> %s::vector) AS score
            FROM brand_screenshots bs
            JOIN brands b ON b.brand_id = bs.brand_id
            ORDER BY bs.embedding <=> %s::vector
            LIMIT 5
            """,
            (vec.tolist(), vec.tolist()),
        )
        top = cur.fetchall()

    # Favicon path: small-image hashing (pHash + MMH3)
    if img.size[0] <= 64 and img.size[1] <= 64:
        # int() cast — mmh3 returns numpy int on some versions; Pydantic
        # can't serialize it and would 500 the entire response.
        mh3 = int(mmh3.hash(img.tobytes()))
        with _pg.cursor() as cur:
            cur.execute(
                "SELECT brand_name FROM brands WHERE %s = ANY(favicon_hashes) LIMIT 1",
                (phash_str,),
            )
            row = cur.fetchone()
            if row:
                favicon = {"matched_brand": row["brand_name"], "phash": phash_str, "mmh3": mh3}

    # Full-screenshot perceptual-hash pre-filter. Cheap deterministic match
    # against brand_screenshots.phash / dhash when populated. Hamming distance
    # ≤ 8 (out of 64 bits) is conservative for pHash → genuine resemblance.
    phash_match = _phash_nearest(in_phash, in_dhash)

    return MatchResponse(
        top=top,
        favicon_match=favicon,
        phash=phash_str,
        dhash=dhash_str,
        phash_match=phash_match,
    )


def _phash_nearest(in_phash, in_dhash, max_distance: int = 8) -> dict[str, Any] | None:
    """Return the brand_screenshots row closest in Hamming distance to the input
    pHash, or None if no stored hash is within max_distance. dHash is consulted
    as a tie-breaker / second-opinion."""
    if _pg is None:
        return None
    with _pg.cursor() as cur:
        cur.execute(
            """
            SELECT b.brand_name, bs.page_label, bs.phash, bs.dhash
            FROM brand_screenshots bs
            JOIN brands b ON b.brand_id = bs.brand_id
            WHERE bs.phash IS NOT NULL
            """
        )
        candidates = cur.fetchall()
    if not candidates:
        return None

    best: dict[str, Any] | None = None
    for row in candidates:
        try:
            stored_p = imagehash.hex_to_hash(row["phash"])
            d_p = in_phash - stored_p
            d_d = max_distance + 1
            if row.get("dhash"):
                stored_d = imagehash.hex_to_hash(row["dhash"])
                d_d = in_dhash - stored_d
        except (ValueError, TypeError):
            continue
        # pHash is the primary discriminator; dHash is a backup. We use the
        # minimum of the two so two-of-three "close enough" signals counts.
        # Cast distances to Python int — imagehash returns numpy.int64 which
        # Pydantic refuses to serialize, breaking the whole /match response.
        score = int(min(d_p, d_d))
        if score <= max_distance and (best is None or score < best["distance"]):
            best = {
                "matched_brand": row["brand_name"],
                "page_label":    row["page_label"],
                "distance":      score,
                "phash_distance": int(d_p),
                "dhash_distance": int(d_d),
            }
    return best


# --- helpers ---


async def _load_image(req: EmbedRequest) -> Image.Image:
    if req.image_b64:
        return Image.open(io.BytesIO(base64.b64decode(req.image_b64))).convert("RGB")
    if req.image_url:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(req.image_url)
            r.raise_for_status()
        return Image.open(io.BytesIO(r.content)).convert("RGB")
    raise HTTPException(400, "image_url or image_b64 required")


def _clip_embed(img: Image.Image):
    assert _model is not None and _preprocess is not None
    with torch.no_grad():
        x = _preprocess(img).unsqueeze(0).to(DEVICE)
        feats = _model.encode_image(x)
        feats = feats / feats.norm(dim=-1, keepdim=True)
    return feats[0].cpu()
