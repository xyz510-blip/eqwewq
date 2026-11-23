"""Image EXIF, XMP/PNG chunk tamper analysis, perceptual hashing (dHash), and reverse image pivots."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

EDITING_SOFTWARE_KEYWORDS = {
    "photoshop", "gimp", "canva", "picsart", "lightroom", "snapseed",
    "corel", "illustrator", "pixelmator", "paint.net", "affinity", "fotor", "remaker", "figma",
}

AI_GENERATOR_KEYWORDS = {
    "midjourney", "stable diffusion", "dall-e", "adobe firefly",
    "comfyui", "automatic1111", "c2pa", "civitai", "novelai",
}


def compute_dhash(img: Image.Image, hash_size: int = 8) -> str:
    """Compute a 64-bit difference hash (dHash) resilient to compression and resizing."""
    gray = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = list(gray.get_flattened_data()) if hasattr(gray, "get_flattened_data") else list(gray.getdata())
    bits = 0
    for row in range(hash_size):
        row_start = row * (hash_size + 1)
        for col in range(hash_size):
            bits = (bits << 1) | (1 if pixels[row_start + col] > pixels[row_start + col + 1] else 0)
    return f"{bits:016x}"


def _rational_to_float(val: Any) -> float:
    try:
        return float(val)
    except Exception:
        if isinstance(val, (tuple, list)) and len(val) == 2 and val[1]:
            return float(val[0]) / float(val[1])
        return 0.0


def _dms_to_decimal(dms: Any, ref: str) -> float | None:
    try:
        if not isinstance(dms, (tuple, list)) or len(dms) < 3:
            return None
        deg = _rational_to_float(dms[0])
        minute = _rational_to_float(dms[1])
        sec = _rational_to_float(dms[2])
        dec = deg + (minute / 60.0) + (sec / 3600.0)
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None


class ImageForensicsModule(BaseOSINTModule):
    """Extracts cryptographic & perceptual hashes, EXIF/XMP/PNG tamper indicators, and GPS coords."""

    name = "image_forensics"
    display_name = "Image EXIF, XMP & Receipt Forensics"
    description = "Analisis EXIF, XMP/PNG chunk editing (Photoshop/Canva/AI), dHash pencocokan foto ulang, GPS, SHA-256, dan reverse image search."
    category = "forensics"
    supported_targets = {TargetType.IMAGE_FILE}

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        img_path = Path(target)
        if not img_path.is_file():
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="error",
                duration_ms=0,
                error=f"File gambar tidak ditemukan: {target}",
            )

        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        root_id = make_entity_id(target_type.value, target)

        raw_bytes = img_path.read_bytes()
        sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
        md5_hex = hashlib.md5(raw_bytes).hexdigest()
        raw_text_probe = raw_bytes[:262144].decode("latin-1", errors="ignore").lower()

        tamper_detected = False

        try:
            with Image.open(img_path) as img:
                width, height = img.size
                img_format = img.format or img_path.suffix.lstrip(".").upper()
                mode = img.mode
                dhash_hex = compute_dhash(img)

                dhash_id = make_entity_id("image_dhash", dhash_hex)
                entities.append(EntityNode(id=dhash_id, label=dhash_hex, entity_type="image_dhash"))
                edges.append(EntityEdge(source=root_id, target=dhash_id, relation="has_perceptual_hash"))

                findings.append(
                    Finding(
                        source=self.name,
                        category="file_forensics",
                        title="Integritas File, Dimensi & Perceptual Hash (dHash)",
                        value=(
                            f"{img_path.name} ({img_format}, {width}x{height}px, {len(raw_bytes):,} bytes) | "
                            f"dHash: {dhash_hex} | SHA-256: {sha256_hex}"
                        ),
                        severity=Severity.INFO,
                        confidence=1.0,
                        metadata={
                            "filename": img_path.name,
                            "format": img_format,
                            "width": width,
                            "height": height,
                            "mode": mode,
                            "size_bytes": len(raw_bytes),
                            "sha256": sha256_hex,
                            "md5": md5_hex,
                            "dhash": dhash_hex,
                        },
                    )
                )

                # Inspect PNG / WebP / JPEG img.info metadata chunks
                info_text = " ".join(
                    f"{k}:{v}" for k, v in (img.info or {}).items() if isinstance(v, (str, bytes))
                ).lower()
                combined_probe = f"{info_text} {raw_text_probe}"

                exif_raw = img.getexif()
                exif_decoded: dict[str, Any] = {}
                gps_ifd: dict[str, Any] = {}
                if exif_raw:
                    for tag_id, value in exif_raw.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        if tag_name == "GPSInfo":
                            try:
                                gps_raw = exif_raw.get_ifd(tag_id)
                                for gid, gval in gps_raw.items():
                                    gname = ExifTags.GPSTAGS.get(gid, str(gid))
                                    gps_ifd[gname] = gval
                            except Exception:
                                pass
                        else:
                            exif_decoded[str(tag_name)] = str(value)[:200]

                if not exif_decoded and not gps_ifd:
                    findings.append(
                        Finding(
                            source=self.name,
                            category="exif_metadata",
                            title="Metadata EXIF Kosong / Dihapus",
                            value="Tidak ada tag EXIF (normal jika gambar dikirim melalui WhatsApp/Telegram atau media sosial).",
                            severity=Severity.INFO,
                            confidence=0.95,
                            risk_delta=0,
                        )
                    )
                else:
                    summary_tags = {
                        k: exif_decoded[k]
                        for k in ("Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist")
                        if k in exif_decoded
                    }
                    findings.append(
                        Finding(
                            source=self.name,
                            category="exif_metadata",
                            title=f"Metadata EXIF Terbaca ({len(exif_decoded)} tag)",
                            value=" | ".join(f"{k}: {v}" for k, v in summary_tags.items()) or "Lihat metadata detail",
                            severity=Severity.INFO,
                            confidence=0.95,
                            metadata={"exif": exif_decoded},
                        )
                    )

                    software = exif_decoded.get("Software", "").lower()
                    matched_ed = [kw for kw in EDITING_SOFTWARE_KEYWORDS if kw in software]
                    if matched_ed:
                        tamper_detected = True
                        findings.append(
                            Finding(
                                source=self.name,
                                category="tamper_alert",
                                title="Indikasi Gambar Diedit Software Grafis (EXIF)",
                                value=f"Tag EXIF Software menunjukkan '{exif_decoded.get('Software')}' — waspadai potensi rekayasa/bukti transfer palsu!",
                                severity=Severity.HIGH,
                                confidence=0.94,
                                risk_delta=25,
                                signal_tier="confirmed_threat",
                                metadata={"software": exif_decoded.get("Software")},
                            )
                        )

                    lat = _dms_to_decimal(gps_ifd.get("GPSLatitude"), str(gps_ifd.get("GPSLatitudeRef", "N")))
                    lon = _dms_to_decimal(gps_ifd.get("GPSLongitude"), str(gps_ifd.get("GPSLongitudeRef", "E")))
                    if lat is not None and lon is not None:
                        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                        findings.append(
                            Finding(
                                source=self.name,
                                category="geolocation",
                                title="Koordinat GPS Ditemukan pada EXIF",
                                value=f"Latitude: {lat}, Longitude: {lon}",
                                url=maps_url,
                                severity=Severity.MEDIUM,
                                confidence=0.95,
                                metadata={"latitude": lat, "longitude": lon},
                            )
                        )

                # XMP / PNG chunk editing detection when EXIF Software didn't already trigger
                if not tamper_detected:
                    matched_chunk_ed = sorted(kw for kw in EDITING_SOFTWARE_KEYWORDS if kw in combined_probe)
                    if matched_chunk_ed:
                        findings.append(
                            Finding(
                                source=self.name,
                                category="tamper_alert",
                                title="Jejak Software Editing Ditemukan di Metadata XMP/Chunk",
                                value=f"Terdeteksi signature editor ({', '.join(matched_chunk_ed)}) — periksa keaslian foto/bukti transfer!",
                                severity=Severity.HIGH,
                                confidence=0.9,
                                risk_delta=25,
                                signal_tier="confirmed_threat",
                                metadata={"matched_editors": matched_chunk_ed},
                            )
                        )

                ai_detected = sorted(kw for kw in AI_GENERATOR_KEYWORDS if kw in combined_probe)
                if ai_detected:
                    findings.append(
                        Finding(
                            source=self.name,
                            category="ai_generated_alert",
                            title="Indikasi Gambar Dihasilkan / Diedit AI",
                            value=f"Metadata file memuat penanda AI generator ({', '.join(ai_detected)}). Waspadai foto profil/KTP palsu.",
                            severity=Severity.MEDIUM,
                            confidence=0.88,
                            risk_delta=20,
                            signal_tier="suspicious",
                            metadata={"ai_markers": ai_detected},
                        )
                    )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="error",
                duration_ms=elapsed,
                error=f"Gagal memproses gambar: {exc}",
            )

        for title, url, desc in (
            ("Google Lens Reverse Image", "https://lens.google.com/", "Unggah foto untuk cek apakah foto profil curian / stok internet"),
            ("Yandex Images Reverse Search", "https://yandex.com/images/", "Sangat akurat untuk pencocokan wajah & foto media sosial"),
            ("TinEye Reverse Image", "https://tineye.com/", "Cari sumber asli dan tanggal kemunculan pertama gambar"),
        ):
            findings.append(
                Finding(
                    source=self.name,
                    category="investigation_link",
                    title=title,
                    value=desc,
                    url=url,
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            )

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"Forensik gambar {img_path.name} selesai ({len(findings)} temuan).",
        )
