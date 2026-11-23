"""Rasterize printable ASCII from Noto Sans Regular at the two UI sizes."""
from pathlib import Path
import sys

from PIL import Image, ImageDraw, ImageFont

atlas = bytearray()
for size, width, height, baseline in ((13, 16, 19, 14), (30, 36, 42, 33)):
    font = ImageFont.truetype(sys.argv[1], size)
    for code in range(32, 127):
        glyph = chr(code)
        cell = Image.new("L", (width, height))
        ImageDraw.Draw(cell).text((1, baseline), glyph, font=font, fill=255, anchor="ls")
        atlas.append(round(font.getlength(glyph)))
        atlas.extend(cell.tobytes())
Path(__file__).with_name("dialog-ascii.bin").write_bytes(atlas)
