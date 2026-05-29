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
import torch
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, Response as FastAPIResponse
from PIL import Image
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

clip_inference_latency = Histogram(
    "xgg_clip_inference_latency_seconds",
    "CLIP embedding inference duration.",
    buckets=[0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
)

clip_inference_total = Counter(
    "xgg_clip_inference_total",
    "CLIP inference calls labeled by result.",
    ["result"],
)

phash_match_distance = Histogram(
    "xgg_phash_match_distance",
    "Distribution of pHash Hamming distances for nearest-neighbor matches.",
    buckets=list(range(0, 17)),  # 0..16 (64-bit hash; threshold is 8)
)

visual_match_total = Counter(
    "xgg_visual_match_total",
    "/match endpoint outcomes labeled by verdict (match vs no_match).",
    ["verdict"],
)

# Inter-service shared-secret authentication (Architecture Audit Finding #3).
# Read once at module import; an empty value disables the check (dev mode).
_INTERNAL_TOKEN: str = os.getenv("XGG_INTERNAL_TOKEN", "")
if not _INTERNAL_TOKEN:
    import logging
    logging.getLogger(__name__).warning(
        "XGG_INTERNAL_TOKEN is not set — inter-service auth DISABLED (dev mode)"
    )

PG_DSN = os.getenv("DATABASE_URL", "postgres://xgg:xgg@localhost:5432/xgg")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
MODEL_NAME = os.getenv("CLIP_MODEL", "ViT-B-32")
PRETRAINED = os.getenv("CLIP_PRETRAINED", "openai")

_model = None
_preprocess = None
# Async connection pool (Finding #8): replaces blocking psycopg.connect() which
# stalled the event loop on every /match request. min_size=2 keeps warm
# connections ready; max_size=10 limits server-side resource use.
_pool: AsyncConnectionPool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _model, _preprocess, _pool
    model, _, preprocess = open_clip.create_model_and_transforms(
        MODEL_NAME, pretrained=PRETRAINED, device=DEVICE
    )
    model.train(False)  # equivalent to .eval(); set inference mode
    _model = model
    _preprocess = preprocess
    _pool = AsyncConnectionPool(
        PG_DSN,
        min_size=2,
        max_size=10,
        kwargs={"autocommit": True, "row_factory": dict_row},
    )
    yield
    if _pool:
        await _pool.close()


app = FastAPI(title="xgg-visual-match", lifespan=lifespan)


@app.get("/metrics")
async def metrics_endpoint() -> FastAPIResponse:
    """Prometheus metrics scrape endpoint. No authentication required."""
    return FastAPIResponse(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def internal_auth_middleware(request: Request, call_next) -> Response:
    """Validate X-Internal-Token on every request except /healthz and /metrics.

    When XGG_INTERNAL_TOKEN is unset the check is skipped (dev mode).
    When set, any missing or mismatched token returns 401 Unauthorized.
    Uses secrets.compare_digest to prevent timing-oracle attacks.
    """
    if request.url.path not in ("/healthz", "/metrics") and _INTERNAL_TOKEN:
        import secrets

        provided = request.headers.get("X-Internal-Token", "")
        if not secrets.compare_digest(provided, _INTERNAL_TOKEN):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


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
    try:
        with clip_inference_latency.time():
            vec = _clip_embed(img)
        clip_inference_total.labels(result="success").inc()
    except Exception:
        clip_inference_total.labels(result="failure").inc()
        raise
    return EmbedResponse(vector=vec.tolist())


@app.post("/match", response_model=MatchResponse)
async def match_image(req: EmbedRequest) -> MatchResponse:
    if _pool is None:
        raise HTTPException(503, "pg not ready")
    img = await _load_image(req)
    try:
        with clip_inference_latency.time():
            vec = _clip_embed(img)
        clip_inference_total.labels(result="success").inc()
    except Exception:
        clip_inference_total.labels(result="failure").inc()
        raise
    favicon = None

    # Perceptual hashes on the full image. Computed always; cheap (a few ms)
    # and useful for analyst drill-down even when no brand pHash is stored.
    in_phash = imagehash.phash(img)
    in_dhash = imagehash.dhash(img)
    phash_str = str(in_phash)
    dhash_str = str(in_dhash)

    async with _pool.connection() as conn:
        async with conn.cursor() as cur:
            # SET LOCAL ensures the probe count applies only to this transaction.
            # lists=5 (migration 0011) → probes=5 gives ~95% recall (Finding #9).
            await cur.execute("SET LOCAL ivfflat.probes = 5")
            await cur.execute(
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
            top = await cur.fetchall()

        # Favicon path: small-image hashing (pHash + MMH3)
        if img.size[0] <= 64 and img.size[1] <= 64:
            # int() cast — mmh3 returns numpy int on some versions; Pydantic
            # can't serialize it and would 500 the entire response.
            mh3 = int(mmh3.hash(img.tobytes()))
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT brand_name FROM brands WHERE %s = ANY(favicon_hashes) LIMIT 1",
                    (phash_str,),
                )
                row = await cur.fetchone()
                if row:
                    favicon = {"matched_brand": row["brand_name"], "phash": phash_str, "mmh3": mh3}

    # Full-screenshot perceptual-hash pre-filter using SQL Hamming distance
    # (Finding #8/#9): replaced Python linear scan with a single SQL query.
    phash_match = await _phash_nearest(in_phash, in_dhash)

    # Record pHash match distance for distribution telemetry.
    if phash_match is not None:
        phash_match_distance.observe(phash_match.get("distance", 0))
        visual_match_total.labels(verdict="match").inc()
    else:
        visual_match_total.labels(verdict="no_match").inc()

    return MatchResponse(
        top=top,
        favicon_match=favicon,
        phash=phash_str,
        dhash=dhash_str,
        phash_match=phash_match,
    )


def _hex_bitcount(h: str) -> int:
    """Population-count over a hex hash string. Bad seeds where the
    rendered screenshot was blank/error produce all-zeros or near-zeros
    hashes; using them as comparison targets makes every other blank/error
    page "match" at 100% (the piratebayproxy → Snapchat / porn.com → Trezor
    misclassifications). Reject hashes with too-few set bits."""
    if not h:
        return 0
    return sum(bin(int(c, 16)).count("1") for c in h if c in "0123456789abcdefABCDEF")


# Minimum acceptable population count for stored brand_screenshots hashes.
# Real content pages produce 28-40 set bits on average; values under 10 are
# almost certainly degenerate seeds. Also reject the same low-quality inputs
# arriving from the live page being scanned.
_MIN_HASH_BITS = 10


async def _phash_nearest(in_phash, in_dhash, max_distance: int = 8) -> dict[str, Any] | None:
    """Return the brand_screenshots row closest in Hamming distance to the input
    pHash using a SQL XOR+popcount query (Finding #8/#9).

    Replaces the previous Python linear scan which pulled ALL rows into memory.
    Postgres bit_count((a::bit(64)) # (b::bit(64))) computes Hamming distance
    server-side; we fetch only the top-5 candidates and apply degenerate-hash
    filtering and dHash tie-breaking on this tiny result set.

    Skips rows whose stored pHash/dHash is degenerate (low bit count) — those
    are bad-seed artifacts that would produce spurious 100% matches against
    any blank/Cloudflare-challenged page.
    """
    if _pool is None:
        return None
    # If the INCOMING image hash is itself degenerate (the live page rendered
    # blank / showed only a Cloudflare challenge / failed to load), nothing
    # useful can come from comparing it to anything. Return no match.
    if _hex_bitcount(str(in_phash)) < _MIN_HASH_BITS or _hex_bitcount(str(in_dhash)) < _MIN_HASH_BITS:
        return None

    # Encode pHash as a 64-bit binary string for Postgres bit casting.
    phash_bits = f"{int(str(in_phash), 16):064b}"

    async with _pool.connection() as conn:
        async with conn.cursor() as cur:
            # XOR-popcount in SQL eliminates the full-table Python scan.
            # bit_count() requires Postgres 14+ (the project target).
            # Fetches top 5 by pHash distance; dHash tie-breaking below.
            await cur.execute(
                """
                SELECT b.brand_name, bs.page_label, bs.phash, bs.dhash,
                       bit_count((bs.phash::bit(64)) # (%s::bit(64))) AS phash_dist
                FROM brand_screenshots bs
                JOIN brands b ON b.brand_id = bs.brand_id
                WHERE bs.phash IS NOT NULL
                ORDER BY phash_dist ASC
                LIMIT 5
                """,
                (phash_bits,),
            )
            candidates = await cur.fetchall()

    if not candidates:
        return None

    best: dict[str, Any] | None = None
    for row in candidates:
        # Defense-in-depth: filter degenerate stored seeds even though the
        # query ordered by distance — bad seeds still surface at low Hamming
        # distance when the live page is also degenerate.
        if _hex_bitcount(row["phash"]) < _MIN_HASH_BITS:
            continue
        if row.get("dhash") and _hex_bitcount(row["dhash"]) < _MIN_HASH_BITS:
            continue
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
