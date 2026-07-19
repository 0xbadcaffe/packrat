# Branding and Visual-Effect Licensing

## Rat emoji

Packrat stores and prints the Unicode `U+1F400 RAT` character (`🐀`). It does
not contain, download, or redistribute an Apple emoji image or the Apple Color
Emoji font. The terminal and operating system choose the rendered glyph. On a
compatible Apple system that character normally uses Apple's installed emoji
font; Linux and Windows may display a different vendor design.

Apple's rendered emoji artwork is not included because the Unicode character
and a vendor's artwork are separate things. Packrat should not bundle an image
copied from Emojipedia's Apple preview without an appropriate license from the
artwork owner.

## Matrix-style opening effect

The opening selector's digital-rain implementation was written independently
for Packrat. It uses Packrat's application tick, an original drop schedule, and
an ASCII-only glyph set. No source code, font, image, preset, or other asset
from [NeoMatrix](https://github.com/IPdotSetAF/NeoMatrix) is included.

NeoMatrix is distributed under GPL-3.0. Visual reference alone does not require
Packrat to include its license. Copying or adapting NeoMatrix implementation or
assets would require a separate compatibility review, preservation of notices,
the GPL-3.0 license text, corresponding source availability, and distribution
of the combined derivative work under GPL-compatible terms. Packrat remains
MIT licensed because no NeoMatrix material was incorporated.
