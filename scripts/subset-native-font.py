"""Optional asset maintenance: python + fonttools; neither is an app runtime."""
import argparse
from pathlib import Path
from fontTools.ttLib import TTFont
from fontTools import subset

parser = argparse.ArgumentParser()
parser.add_argument("--font", required=True, help="NotoSansCJK-Regular.ttc from the Noto CJK distribution")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
font = TTFont(args.font, fontNumber=0)
text = "".join(p.read_text() for p in (root / "desktop/assets/locales").glob("*.json"))
text += (root / "desktop/src/i18n.rs").read_text() + "☀☾⚙↑↓●✓—→"
options = subset.Options()
options.name_IDs = ["*"]
options.name_legacy = True
options.name_languages = ["*"]
subsetter = subset.Subsetter(options=options)
subsetter.populate(text=text)
subsetter.subset(font)
for record in font["name"].names:
    if record.nameID in (1, 3, 4, 6):
        name = "GenyraUIFallback" if record.nameID == 6 else "Genyra UI Fallback"
        record.string = name.encode(record.getEncoding(), errors="replace")
font.save(root / "desktop/assets/fonts/GenyraUIFallback.otf")
