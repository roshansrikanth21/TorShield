# TorShield IEEE manuscript

This directory contains the v4 manuscript, not the original XOR draft. The
paper is written around the code in `module/LKM/` and the evidence log in
`TO-DO.md`.

## Files

| File | Purpose |
|---|---|
| `TorShield_IEEE.tex` | IEEEtran conference source. |
| `references.bib` | Bibliography for the manuscript. |
| `TorShield_IEEE.pdf` | Compiled 7-page manuscript (US Letter). |
| `CLAIM_EVIDENCE.md` | Claim-to-evidence audit and the list of withdrawn draft claims. |
| `archive/TorShield_IEEE_2026-06-27_initial_draft.{docx,pdf}` | Preserved initial XOR draft, for provenance only. |

## Build

Requires a TeX Live installation with `IEEEtran`, `tikz`, `booktabs`, and
`hyperref`; on Ubuntu 24.04:

```bash
sudo apt-get install -y texlive-latex-base texlive-latex-recommended \
  texlive-publishers texlive-fonts-recommended texlive-pictures latexmk
cd paper
latexmk -pdf -interaction=nonstopmode -halt-on-error TorShield_IEEE.tex
```

The checked-in PDF was built with pdfTeX 1.40.25 (TeX Live 2023) and is seven
pages. It is intentionally not compressed to a six-page limit because the
target venue is not yet fixed.

## What changed from the initial draft

- The evaluated system is the ChaCha20--Poly1305 UDP tunnel with per-peer keys,
  replay protection, padding, and three steering paths, not the single-byte XOR
  module.
- The abstract, introduction, related work, design, evaluation, security
  analysis, and conclusion were rewritten against the v4 code and captured
  results.
- All unverified draft numbers were removed: 1% CPU, 0.5 ms/packet, 50 KB
  footprint, 5% throughput loss, 72-hour stability, and the multi-distribution
  kernel matrix. See `CLAIM_EVIDENCE.md`.
- The old manuscript's duplicated code listings, stray line numbers,
  `Table ??`, and figure placeholders are gone.
- The paper now states explicitly that TorShield is not Tor, provides no
  anonymity, has no handshake or forward secrecy, and is not a replacement for
  WireGuard or IPsec.

## Before submission

1. Confirm the target IEEE venue, page limit, and whether the 7-page version
   must be cut to 6 pages.
2. Confirm the author order and affiliation with the co-author.
3. Decide whether to add a bare-metal throughput run. The current performance
   numbers are from a WSL2/Hyper-V VM, and the paper says so.
4. If the venue expects a figure, add a compact architecture diagram; the
   current manuscript relies on tables and prose.
5. Rebuild the PDF after any edit and run:
   `grep -nE 'Overfull|Undefined|undefined|Warning' TorShield_IEEE.log`.
6. Keep `CLAIM_EVIDENCE.md` in sync with any new result. Do not add a number to
   the paper without a captured log.
