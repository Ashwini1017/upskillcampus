"""Export project source files to a single PDF (run: python export_code_pdf.py)."""
from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).parent.resolve()
OUTPUT = ROOT / "password_manager_source_code.pdf"
FILES = [
    "README.md",
    "requirements.txt",
    "auth.py",
    "encryption.py",
    "password_manager.py",
    "utils.py",
    "main.py",
    "test_password_manager.py",
]


def chunk_lines(text: str, width: int = 96) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.expandtabs(4)
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return out


def main() -> None:
    pdf = FPDF(orientation="portrait", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.set_margins(12, 12, 12)

    for fname in FILES:
        path = ROOT / fname
        if not path.is_file():
            continue
        pdf.add_page()
        pdf.set_font("Courier", "B", 11)
        pdf.multi_cell(0, 5, f"=== {fname} ===")
        pdf.ln(1)
        pdf.set_font("Courier", size=7)
        content = path.read_text(encoding="utf-8")
        for line in chunk_lines(content):
            pdf.cell(0, 3.5, line, new_x="LMARGIN", new_y="NEXT")

    pdf.output(OUTPUT.as_posix())
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
