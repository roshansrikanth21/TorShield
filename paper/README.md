# TorShield IEEE manuscript

This directory contains the v4 manuscript, not the original XOR draft. The
paper is written around the code in `module/LKM/` and the evidence log in
`TO-DO.md`.

## Files

| File | Purpose |
|---|---|
| `TorShield_IEEE.tex` | Full IEEEtran conference manuscript (archival version). |
| `TorShield_IEEE.pdf` | Compiled full manuscript, exactly 6 pages (US Letter). |
| `TorShield_RAIT2027_DC.tex` | RAIT 2027 Doctoral Consortium extended abstract source. |
| `TorShield_RAIT2027_DC.pdf` | Compiled Doctoral Consortium abstract, exactly 4 pages including references (US Letter). |
| `references.bib` | Shared bibliography for both versions. |
| `CLAIM_EVIDENCE.md` | Claim-to-evidence audit and the list of withdrawn draft claims. |
| `archive/TorShield_IEEE_2026-06-27_initial_draft.{docx,pdf}` | Preserved initial XOR draft, for provenance only. |

## Build

Requires a TeX Live installation with `IEEEtran`, `tikz`, `booktabs`, and
`hyperref`; on Ubuntu 24.04:

```bash
sudo apt-get install -y texlive-latex-base texlive-latex-recommended \
  texlive-publishers texlive-fonts-recommended texlive-pictures latexmk
cd paper

# Full archival manuscript: exactly 6 pages.
latexmk -pdf -interaction=nonstopmode -halt-on-error TorShield_IEEE.tex

# RAIT 2027 Doctoral Consortium abstract: exactly 4 pages including references.
latexmk -pdf -interaction=nonstopmode -halt-on-error TorShield_RAIT2027_DC.tex
```

The checked-in PDFs were built with pdfTeX (TeX Live 2023) and are US Letter.
The full manuscript is six pages. The Doctoral Consortium version is four pages
including references; it uses the same `IEEEtran` class and the official IEEE
conference template's `\documentclass[conference]{IEEEtran}` settings.

## RAIT 2027 Doctoral Consortium

- **Submission format:** one PDF containing, in order, the **4-page extended
  abstract** (references included), a **1-page resume**, and a **1-page
  supervisor recommendation**. Total: **6 pages** in one file.
- **Abstract source/PDF:** `TorShield_RAIT2027_DC.tex` and
  `TorShield_RAIT2027_DC.pdf`. The PDF is exactly four pages and uses two
  side-by-side author blocks (Roshan Srikanth and Dr. S. UdhayaKumar), as
  requested.
- **Review model:** single-blind, so author names, affiliations, and emails are
  included. The main conference is double-blind; do not reuse this author block
  there.
- **Domain:** 03 — Big Data Analytics, Cloud Computing & Cyber Security.
- **Similarity:** must be below 10%. Run the venue's checker on the complete
  six-page submission PDF, not only on the four-page abstract.
- **Deadline:** November 2, 2026, Anywhere on Earth (AoE). Notification:
  November 30, 2026. Camera-ready: December 15, 2026.
- **Eligibility:** registered Ph.D. student in the first three years; at least
  one author must register and present in person; no remote presentation and no
  travel grants.
- **Missing before submission:** the one-page resume and the one-page
  supervisor recommendation are not in this repository. Merge them with the
  four-page abstract only after both are final.
- **Merge order and check:** keep the abstract first, then the resume, then the
  supervisor recommendation:
  ```bash
  pdfunite TorShield_RAIT2027_DC.pdf resume.pdf supervisor_lor.pdf \
    TorShield_RAIT2027_DC_submission.pdf
  pdfinfo TorShield_RAIT2027_DC_submission.pdf | grep Pages   # must be 6
  ```
  Do not add a cover page or a table of contents.

Do not submit the six-page `TorShield_IEEE.pdf` to the Doctoral Consortium. It
is the archival full paper, not the four-page Doctoral Consortium abstract.

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
- The old XOR architecture diagram and output screenshots are replaced by one
  compact v4 datapath figure (Fig. 1) showing the shared AEAD wire format and
  the fail-closed TC guard.
- The paper now states explicitly that TorShield is not Tor, provides no
  anonymity, has no handshake or forward secrecy, and is not a replacement for
  WireGuard or IPsec.

## Before submission

1. For the Doctoral Consortium, use only
   `TorShield_RAIT2027_DC.pdf` plus the one-page resume and one-page supervisor
   recommendation, merged into a single PDF. The full `TorShield_IEEE.pdf` is
   not the Doctoral Consortium submission.
2. Confirm the author list and email addresses: Roshan Srikanth and
   Dr. S. UdhayaKumar. The address `roshansrikanth21@gmail.com` matches the
   repository Git configuration. The Doctoral Consortium is single-blind, so
   include both names, the affiliation, and both emails on page 1.
3. Confirm Ph.D. registration and that the applicant is within the first three
   years of the doctoral program; this is an eligibility condition, not a
   formatting detail.
4. Decide whether to add a bare-metal throughput run. The current performance
   numbers are from a WSL2/Hyper-V VM, and both versions say so.
5. Both versions already include one compact v4 datapath figure (Fig. 1). Do
   not reuse the old XOR diagrams or the `/proc/xor_key` screenshots.
6. Rebuild both PDFs after any edit and check page counts and warnings:
   ```bash
   pdfinfo TorShield_IEEE.pdf | grep Pages
   pdfinfo TorShield_RAIT2027_DC.pdf | grep Pages
   grep -nE 'Overfull|Undefined|undefined|Warning' TorShield_IEEE.log \
     TorShield_RAIT2027_DC.log
   ```
7. Keep `CLAIM_EVIDENCE.md` in sync with any new result. Do not add a number to
   either paper without a captured log.
8. Run the similarity check on the final merged six-page PDF and confirm it is
   below 10% before the November 2, 2026 AoE deadline.
