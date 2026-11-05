"""Create original Molcer OS vector branding and OLED-black raster candidates.

Only Python's standard library is used. The geometric letter strokes are part
of this source; no font, image, or other artwork is downloaded or redistributed.
The stock ROM and connected devices are never opened or modified.
"""
import argparse
import hashlib
import io
import json
import math
import pathlib
import re
import struct
import zipfile
import zlib


BASE_SHA256 = 'bd19c93fa7c1cb90ed194c5cc2ebfe786f55f1382b172e344522ca805c63f1ea'
DISPLAY_SIZE = (1440, 3200)
DISPLAY_SOURCE = 'https://www.mi.com/global/product/xiaomi-15-ultra/specs/'
FORMAT_SOURCE = ('https://android.googlesource.com/platform/frameworks/base/'
                 '+/refs/heads/main/cmds/bootanimation/FORMAT.md')
MAX_BOOT_ZIP = 4 * 1024**2
MAX_PIXELS = 16 * 1024**2
STATIC_FPS = 1

# Original, limited geometric lettering for this wordmark, not a font file.
# Coordinates use a 14 x 20 drawing grid. Independent polylines remain separate.
GLYPHS = {
    'M': [[(0, 20), (0, 0), (7, 11), (14, 0), (14, 20)]],
    'O': [[(3, 0), (11, 0), (14, 3), (14, 17), (11, 20), (3, 20), (0, 17), (0, 3), (3, 0)]],
    'L': [[(0, 0), (0, 20), (14, 20)]],
    'C': [[(14, 3), (11, 0), (3, 0), (0, 3), (0, 17), (3, 20), (11, 20), (14, 17)]],
    'E': [[(14, 0), (0, 0), (0, 20), (14, 20)], [(0, 10), (11, 10)]],
    'R': [[(0, 20), (0, 0), (10, 0), (14, 4), (14, 7), (10, 10), (0, 10)], [(7, 10), (15, 20)]],
    'S': [[(14, 3), (11, 0), (3, 0), (0, 3), (0, 7), (3, 10), (11, 10), (14, 13),
           (14, 17), (11, 20), (3, 20), (0, 17)]],
}
MARK = [(0, 108), (0, 0), (24, 0), (64, 56), (104, 0), (128, 0),
        (128, 108), (104, 108), (104, 40), (64, 94), (24, 40), (24, 108)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dimensions(width, height):
    if (type(width) is not int or type(height) is not int or
            not 64 <= width <= 4096 or not 64 <= height <= 4096 or
            width > height or width * height > MAX_PIXELS):
        raise ValueError('Expected bounded portrait image dimensions')


def parse_stock_desc(text):
    if not isinstance(text, str) or not 0 < len(text.encode('utf-8')) <= 65536 or '\0' in text:
        raise ValueError('Missing or oversized stock bootanimation description')
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if len(lines) < 2:
        raise ValueError('Stock description needs a header and animation part')
    header = lines[0].split()
    if len(header) not in (3, 4) or any(not word.isdecimal() for word in header):
        raise ValueError('Unsupported stock bootanimation header')
    width, height, fps = map(int, header[:3])
    dimensions(width, height)
    if not 1 <= fps <= 240 or (len(header) == 4 and header[3] not in ('0', '1')):
        raise ValueError('Unsupported stock fps/progress header')
    parts = []
    for line in lines[1:]:
        fields = line.split()
        if fields[0] == 'dynamic_colors':
            continue
        if (len(fields) < 4 or fields[0] not in ('p', 'c', 'f') or
                not fields[1].isdecimal() or not fields[2].isdecimal() or
                not re.fullmatch(r'[A-Za-z0-9_-]+', fields[3])):
            raise ValueError('Unsupported stock animation part; inspect evidence before building')
        parts.append({'type': fields[0], 'count': int(fields[1]),
                      'pause': int(fields[2]), 'path': fields[3]})
    if not parts or len(parts) > 64:
        raise ValueError('Invalid stock animation part count')
    return {'width': width, 'height': height, 'fps': fps, 'parts': parts}


def validate_evidence(evidence):
    if (evidence.get('schema') != 1 or evidence.get('phone_accessed') is not False or
            evidence.get('source_archive_hash_verified') is not True or
            evidence.get('source_archive_sha256') != BASE_SHA256):
        raise ValueError('Expected authenticated offline Android 17 branding evidence')
    stock = evidence.get('bootanimation', {})
    path = stock.get('path', '')
    relative = pathlib.PurePosixPath(path.lstrip('/'))
    if (not path or '\\' in path or '..' in relative.parts or
            relative.name != 'bootanimation.zip' or not relative.parts):
        raise ValueError('Unsafe or missing inspected stock bootanimation path')
    for key in ('sha256', 'desc_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', stock.get(key, '')):
            raise ValueError('Missing stock bootanimation/description hash')
    desc = stock.get('desc', '')
    if not isinstance(desc, str) or digest(desc.encode('utf-8')) != stock['desc_sha256']:
        raise ValueError('Stock description does not match inspected hash')
    return parse_stock_desc(desc)


def fill_polygon(canvas, width, height, points):
    """Rasterize a polygon at pixel centres, within the small supersampled patch."""
    top = max(0, math.ceil(min(y for _, y in points) - 0.5))
    bottom = min(height, math.ceil(max(y for _, y in points) - 0.5))
    edges = list(zip(points, points[1:] + points[:1]))
    for y in range(top, bottom):
        scan = y + 0.5
        intersections = []
        for (x0, y0), (x1, y1) in edges:
            if (y0 <= scan < y1) or (y1 <= scan < y0):
                intersections.append(x0 + (scan - y0) * (x1 - x0) / (y1 - y0))
        intersections.sort()
        for index in range(0, len(intersections) - 1, 2):
            left = max(0, math.ceil(intersections[index] - 0.5))
            right = min(width, math.ceil(intersections[index + 1] - 0.5))
            if right > left:
                canvas[y * width + left:y * width + right] = b'\xff' * (right - left)


def stroke(canvas, width, height, points, thickness):
    radius = thickness / 2
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        length = math.hypot(x1 - x0, y1 - y0)
        if not length:
            continue
        nx, ny = -(y1 - y0) * radius / length, (x1 - x0) * radius / length
        fill_polygon(canvas, width, height,
                     [(x0 + nx, y0 + ny), (x1 + nx, y1 + ny),
                      (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)])
    for x, y in points:
        circle = [(x + radius * math.cos(i * math.tau / 16),
                   y + radius * math.sin(i * math.tau / 16)) for i in range(16)]
        fill_polygon(canvas, width, height, circle)


def vector_shapes():
    mark_scale = 1.4
    mark_left = (420 - 128 * mark_scale) / 2
    polygon = [(mark_left + x * mark_scale, 30 + y * mark_scale) for x, y in MARK]
    text_scale, advance, space = 1.5, 23, 14
    word = 'MOLCER OS'
    text_width = (8 * advance + space - (advance - 14)) * text_scale
    cursor = (420 - text_width) / 2
    paths = []
    for char in word:
        if char == ' ':
            cursor += space * text_scale
            continue
        for path in GLYPHS[char]:
            paths.append([(cursor + x * text_scale, 232 + y * text_scale) for x, y in path])
        cursor += advance * text_scale
    return polygon, paths, 1.5 * text_scale


def render_boot_frame(width, height):
    dimensions(width, height)
    scale = width / 1440
    patch_width, patch_height = max(1, round(420 * scale)), max(1, round(310 * scale))
    # Supersample only the small vector mark/wordmark, not the full black screen.
    aa = 4
    high_width, high_height = patch_width * aa, patch_height * aa
    high = bytearray(high_width * high_height)
    polygon, paths, thickness = vector_shapes()
    factor = scale * aa
    transform = lambda points: [(x * factor, y * factor) for x, y in points]
    fill_polygon(high, high_width, high_height, transform(polygon))
    for path in paths:
        stroke(high, high_width, high_height, transform(path), thickness * factor)
    patch = bytearray(patch_width * patch_height)
    for y in range(patch_height):
        for x in range(patch_width):
            total = sum(high[(y * aa + sy) * high_width + x * aa + sx]
                        for sy in range(aa) for sx in range(aa))
            patch[y * patch_width + x] = (total + aa * aa // 2) // (aa * aa)
    canvas = bytearray(width * height)
    left, top = (width - patch_width) // 2, round(height * 0.48 - patch_height / 2)
    if top < 0 or top + patch_height > height:
        raise ValueError('Brand composition does not fit inspected stock dimensions')
    for y in range(patch_height):
        offset = (top + y) * width + left
        canvas[offset:offset + patch_width] = patch[y * patch_width:(y + 1) * patch_width]
    if canvas.count(0) < len(canvas) * 0.98:
        raise ValueError('Unexpectedly large illuminated region')
    return bytes(canvas)


def png_chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)


def encode_png(width, height, grayscale):
    dimensions(width, height)
    if len(grayscale) != width * height:
        raise ValueError('Raster byte length differs from dimensions')
    compressor = zlib.compressobj(9)
    compressed = bytearray()
    for y in range(height):
        row = grayscale[y * width:(y + 1) * width]
        rgb = bytearray(width * 3)
        rgb[0::3] = row
        rgb[1::3] = row
        rgb[2::3] = row
        compressed.extend(compressor.compress(b'\0' + rgb))
    compressed.extend(compressor.flush())
    # RGB8, opaque, non-interlaced; no palette, metadata, profiles or external references.
    return (b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0))
            + png_chunk(b'IDAT', bytes(compressed)) + png_chunk(b'IEND', b''))


def render_svg(width, height):
    dimensions(width, height)
    scale = width / 1440
    left = (width - 420 * scale) / 2
    top = height * 0.48 - 310 * scale / 2
    polygon, paths, thickness = vector_shapes()
    points = lambda data: ' '.join(f'{x:.3f},{y:.3f}' for x, y in data)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             '<title>Molcer OS</title><rect width="100%" height="100%" fill="#000000"/>',
             f'<g transform="translate({left:.3f} {top:.3f}) scale({scale:.6f})">',
             f'<polygon points="{points(polygon)}" fill="#ffffff"/>']
    for path in paths:
        parts.append(f'<polyline points="{points(path)}" fill="none" stroke="#ffffff" '
                     f'stroke-width="{thickness}" stroke-linecap="round" stroke-linejoin="round"/>')
    return ('\n'.join(parts) + '\n</g></svg>\n').encode('utf-8')


def boot_archive(width, height, frame):
    desc = f'{width} {height} {STATIC_FPS}\np 0 0 part0 #000000\n'.encode('ascii')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, data in [('desc.txt', desc), ('part0/00000.png', frame)]:
            info = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    data = output.getvalue()
    if len(data) > MAX_BOOT_ZIP:
        raise ValueError('Boot animation exceeds 4 MiB bound')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.testzip() is not None or archive.namelist() != ['desc.txt', 'part0/00000.png']:
            raise ValueError('Generated boot animation failed ZIP integrity check')
        if any(item.compress_type != zipfile.ZIP_STORED for item in archive.infolist()):
            raise ValueError('Boot animation members must be stored')
    return data, desc.decode('ascii')


def build(output, evidence=None, preview_only=False):
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('Use a fresh branding output directory')
    if preview_only:
        if evidence is not None:
            raise ValueError('Preview mode does not consume or claim stock evidence')
        width, height = DISPLAY_SIZE
        source = None
    else:
        if evidence is None:
            raise ValueError('Stock description evidence is required before creating bootanimation.zip')
        source = validate_evidence(evidence)
        width, height = source['width'], source['height']
    raster = render_boot_frame(width, height)
    frame = encode_png(width, height, raster)
    wallpaper = encode_png(*DISPLAY_SIZE, bytes(DISPLAY_SIZE[0] * DISPLAY_SIZE[1]))
    assets = {'boot-preview.png': frame, 'boot-preview.svg': render_svg(width, height),
              'wallpaper.png': wallpaper}
    desc = None
    if not preview_only:
        assets['bootanimation.zip'], desc = boot_archive(width, height, frame)
    report = {
        'schema': 1, 'name': 'Molcer OS',
        'status': 'visual-preview-only' if preview_only else 'offline-branding-candidates-built',
        'boot_dimensions': {'width': width, 'height': height},
        'boot_dimensions_source': DISPLAY_SOURCE if preview_only else 'authenticated-stock-desc',
        'stock_bootanimation': evidence['bootanimation'] if evidence else None,
        'stock_desc_parameters': source, 'output_fps': STATIC_FPS if not preview_only else None,
        'output_desc': desc, 'frame_count': 1, 'animated_changes_between_frames': False,
        'background_rgb': '#000000', 'foreground_rgb': '#ffffff',
        'edge_antialiasing': 'neutral grayscale coverage',
        'exact_black_pixel_fraction': raster.count(0) / len(raster),
        'stock_timing_and_part_structure_preserved': False,
        'loop_design': 'One static frame in an interruptible p part; stops when boot completion is signalled.',
        'wallpaper': {'width': DISPLAY_SIZE[0], 'height': DISPLAY_SIZE[1],
                      'every_pixel_rgb': '#000000', 'dimensions_source': DISPLAY_SOURCE,
                      'installation_destination_verified': False},
        'design_source': 'Original polygons and geometric letter strokes in build_brand_assets.py',
        'font_dependency': None, 'third_party_artwork': False,
        'format_source': FORMAT_SOURCE, 'maximum_boot_zip_bytes': MAX_BOOT_ZIP,
        'phone_accessed': False, 'stock_files_modified': False,
        'runtime_verified': False, 'performance_improvement_measured': False,
        'installed_into_rom': False, 'ready_to_flash': False,
        'assets': {name: {'size': len(data), 'sha256': digest(data)} for name, data in assets.items()},
    }
    if evidence:
        report['evidence_canonical_json_sha256'] = digest(json.dumps(evidence, sort_keys=True).encode('utf-8'))
    output.mkdir(parents=True)
    for name, data in assets.items():
        with (output / name).open('xb') as stream:
            stream.write(data)
    (output / 'branding-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=pathlib.Path,
                        help='Authenticated stock path/desc JSON; required except for visual preview')
    parser.add_argument('--preview-only', action='store_true')
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('out/brand-assets'))
    args = parser.parse_args()
    if args.preview_only == bool(args.evidence):
        parser.error('Choose either --evidence or --preview-only')
    evidence = None
    if args.evidence:
        if args.evidence.stat().st_size > 1024**2:
            raise ValueError('Branding evidence exceeds 1 MiB')
        evidence = json.loads(args.evidence.read_text(encoding='utf-8'))
    report = build(args.output, evidence, args.preview_only)
    print(json.dumps({'status': report['status'], 'output': str(args.output), 'assets': report['assets']}))


if __name__ == '__main__':
    main()
