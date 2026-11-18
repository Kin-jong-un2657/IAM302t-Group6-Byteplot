"""Fetch bounded publisher ZIPs only. Never parse, extract or execute PE on Windows."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import argparse
import csv
import hashlib
import json
import re
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
MAX_ARCHIVE = 8 * 1024**2
MAX_PAGE = 2 * 1024**2
NIR_NAMES = (
    "WinExplorer", "CurrProcess", "MyUninstaller", "FileDate Changer", "SysExporter", "WinUpdatesList",
    "MMCompView", "JRView", "HashMyFiles", "BulkFileChanger", "FolderTimeUpdate", "FileAccessErrorView",
    "SpecialFoldersView", "HotKeysList", "WinCrashReport", "DriverView", "InstalledDriversList",
    "RegFromApp", "RegFileExport", "ShellBagsView", "UserAssistView", "ExecutedProgramsList",
    "NetworkInterfacesView", "NetResView", "AdapterWatch", "MACAddressView", "IPNetInfo",
    "WhoisThisDomain", "WinFontsView", "AlternateStreamView", "ActiveXHelper", "GACView",
    "DLL Export Viewer", "MUICacheView", "FoldersReport", "ExeInfo", "MyLastSearch", "FileTypesView",
    "FolderChangesView", "FileActivityWatch", "RegDllView", "WinLister", "GDIView", "HeapMemView",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.href = None; self.label = []; self.words = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.href = dict(attrs).get("href"); self.label = []

    def handle_data(self, data):
        self.words.append(data)
        if self.href:
            self.label.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.href:
            self.links.append((self.href, "".join(self.label).strip())); self.href = None


def valid_url(url, hosts):
    p = urlparse(url)
    if p.scheme != "https" or p.hostname not in hosts or p.username or p.password or p.port not in {None, 443}:
        raise ValueError("Download must stay on the allowlisted publisher HTTPS host")
    return url


class PublisherRedirect(HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        valid_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, hosts, limit=MAX_PAGE):
    valid_url(url, hosts)
    opener = build_opener(PublisherRedirect(hosts))
    req = Request(url, headers={"User-Agent": "IAM302t-Group6-static-research/1.0"})
    with opener.open(req, timeout=20) as response:
        valid_url(response.url, hosts)
        size = response.headers.get("Content-Length")
        if size and int(size) > limit:
            raise ValueError("Publisher object exceeds intake size bound")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Publisher object exceeds intake size bound")
        return data, response.url


def save(path, data):
    with path.open("xb") as f:
        f.write(data)


def page_links(raw):
    result = Links(); result.feed(raw.decode("utf-8", errors="replace")); return result


def nir_download(page_url, parsed):
    found = []
    for href, label in parsed.links:
        try:
            url = urljoin(page_url, href)
            p = urlparse(url)
        except ValueError:
            continue  # Ignore malformed, unrelated publisher-page links.
        if p.hostname not in {"www.nirsoft.net", "nirsoft.net"}:
            continue
        if p.path.startswith("/utils/") and p.path.lower().endswith(".zip"):
            low = (p.path + " " + label).casefold()
            if any(v in low for v in ("x64", "64-bit", "arm64", "language", "translate", "non-unicode", "nonunicode")):
                continue
            if re.search(r"(?:src|source)\.zip$|[_-]src", p.path, re.I):
                continue
            if label.strip().casefold().startswith("download"):
                found.append(url.replace("http://", "https://", 1))
    found = list(dict.fromkeys(found))
    if len(found) != 1:
        raise ValueError("Publisher page does not have exactly one reviewed 32-bit program ZIP")
    return found[0]


def published_nir_hash(raw, filename):
    text = " ".join(page_links(raw).words)
    block = re.search(r"Filename\s+" + re.escape(filename) + r"\s+(.*?)(?=Filename|$)", text, re.S)
    match = re.search(r"SHA256\s+Hash\s+([a-fA-F0-9]{64})", block.group(1)) if block else None
    return match.group(1).lower() if match else None


def acquire(spec, out):
    slug = spec["slug"]
    folder = out / "sources" / slug
    folder.mkdir()
    hosts = set(spec["hosts"])
    page, effective_page = fetch(spec["page"], hosts)
    save(folder / "publisher_page.html", page)
    if spec["publisher"] == "NirSoft":
        url = nir_download(effective_page, page_links(page))
    else:
        url = spec["download"]
        if not any(urljoin(effective_page, href) == url for href, _ in page_links(page).links):
            raise ValueError("Exact ZIP is not linked from its publisher page")
    valid_url(url, hosts)
    filename = Path(urlparse(url).path).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.zip", filename, re.I):
        raise ValueError("Only publisher ZIP archives are accepted")
    expected, hash_source, hash_error = None, "", ""
    if spec["publisher"] == "NirSoft":
        hash_source = "https://www.nirsoft.net/hash_check/?software=" + Path(filename).stem
        try:
            hash_page, _ = fetch(hash_source, hosts)
            save(folder / "publisher_hashes.html", hash_page)
            expected = published_nir_hash(hash_page, filename)
        except Exception as exc:
            hash_error = type(exc).__name__
    elif spec.get("hash_url"):
        hash_source = spec["hash_url"]
        hash_page, _ = fetch(hash_source, hosts)
        save(folder / "publisher_hashes.txt", hash_page)
        for line in hash_page.decode("utf-8", errors="strict").splitlines():
            if filename in line:
                match = re.search(r"\b([0-9a-fA-F]{64})\b", line)
                if match:
                    expected = match.group(1).lower()
    raw, effective = fetch(url, hosts, MAX_ARCHIVE)
    save(folder / filename, raw)
    observed = sha(raw)
    if expected and observed != expected:
        raise ValueError("Publisher archive checksum mismatch; archive retained but NOT admitted")
    # Check container metadata only; per-member CRC checks happen during the VM audit.
    with zipfile.ZipFile(folder / filename) as z:
        infos = z.infolist()
        if len(infos) > 1000 or len({i.filename for i in infos}) != len(infos):
            raise ValueError("Duplicate/excessive publisher ZIP members")
        if sum(i.file_size for i in infos) > 64 * 1024**2:
            raise ValueError("Publisher ZIP expands beyond intake bound")
    result = dict(program=spec["program"], publisher=spec["publisher"], software_lineage=spec["lineage"],
        archive_path=str((folder / filename).relative_to(out)).replace("\\", "/"), archive_sha256=observed,
        archive_bytes=len(raw), source_url=effective, publisher_page=effective_page,
        publisher_page_sha256=sha(page), published_hash_url=hash_source,
        published_archive_sha256=expected, publisher_hash_verified=expected is not None,
        hash_lookup_error_type=hash_error,
        transport_authentication="publisher HTTPS; archive hash is not independent signature verification",
        license_basis=spec["license_basis"],
        status="CANDIDATE_ARCHIVE_ONLY_PENDING_VM_STATIC_AUDIT", member_count=len(infos),
        executable_members_listed=sum(i.filename.casefold().endswith(".exe") for i in infos),
        PE_parsed=False, software_executed=False, training_admitted=0)
    save(folder / "source_receipt.json", json.dumps(result, indent=2).encode())
    return result


def curate(index, existing_programs):
    links = page_links(index).links
    specs = []
    explicit = {"MyUninstaller": "https://www.nirsoft.net/utils/myuninst.html",
                "FileDate Changer": "https://www.nirsoft.net/utils/filedatech.html",
                "MMCompView": "https://www.nirsoft.net/utils/mmview.html",
                "JRView": "https://www.nirsoft.net/utils/javaview.html"}
    for name in NIR_NAMES:
        if re.sub(r"[^a-z0-9]", "", name.casefold()) in existing_programs:
            continue
        matches = [urljoin("https://www.nirsoft.net/utils/", url) for url, label in links
                   if re.match(re.escape(name)+r"(?:\s|$|\-)", label, re.I)]
        page = matches[0] if matches else explicit.get(name)
        if page:
            valid_url(page, {"www.nirsoft.net", "nirsoft.net"})
            slug = re.sub(r"[^a-z0-9]", "", name.casefold())
            specs.append(dict(program=name, slug=slug, publisher="NirSoft", page=page,
                hosts=["www.nirsoft.net", "nirsoft.net"], lineage="NirSoft:"+slug,
                license_basis="Publisher freeware terms; preserve complete original archive and notices; private research only"))
    specs.extend([
        dict(program="Everything", slug="everything", publisher="voidtools", page="https://www.voidtools.com/downloads/",
             download="https://www.voidtools.com/Everything-1.4.1.1032.x86.zip",
             hash_url="https://www.voidtools.com/Everything-1.4.1.1032.sha256",
             hosts=["www.voidtools.com", "voidtools.com"], lineage="voidtools:everything",
             license_basis="Publisher MIT license at https://www.voidtools.com/License.txt; complete package preserved"),
        dict(program="Notepad2", slug="notepad2", publisher="Florian Balmer", page="https://www.flos-freeware.ch/notepad2.html",
             download="https://www.flos-freeware.ch/zip/notepad2_4.2.25_x86.zip",
             hosts=["www.flos-freeware.ch", "flos-freeware.ch"], lineage="FlorianBalmer:notepad2",
             license_basis="Publisher distribution with original notices preserved; private research only"),
    ])
    if len(specs) > 48 or len({s["slug"] for s in specs}) != len(specs):
        raise ValueError("Bounded program allowlist differs")
    return specs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--existing-candidates", required=True, type=Path)
    parser.add_argument("--previous-candidates", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "sources").mkdir()
    existing = json.loads(args.existing_candidates.read_text(encoding="utf-8"))["records"]
    existing_programs = {re.sub(r"[^a-z0-9]", "", r.get("source_program", "").casefold()) for r in existing}
    with args.previous_candidates.open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            existing_programs.add(re.sub(r"[^a-z0-9]", "", row.get("source_program", "").casefold()))
    index, _ = fetch("https://www.nirsoft.net/utils/", {"www.nirsoft.net", "nirsoft.net"})
    save(args.out / "publisher_index.html", index)
    specs = curate(index, existing_programs)
    save(args.out / "FROZEN_PUBLISHER_ALLOWLIST.json", json.dumps(specs, indent=2).encode())
    records, errors = [], []
    with ThreadPoolExecutor(max_workers=3) as executor:
        jobs = {executor.submit(acquire, spec, args.out): spec for spec in specs}
        for future in as_completed(jobs):
            spec = jobs[future]
            try:
                result = future.result(); records.append(result)
                print(json.dumps(dict(program=result["program"], status="ARCHIVE_ACQUIRED_NOT_AUDITED",
                                      bytes=result["archive_bytes"], publisher_hash_verified=result["publisher_hash_verified"])), flush=True)
            except Exception as exc:
                errors.append(dict(program=spec["program"], error_type=type(exc).__name__, error=str(exc)))
                print(json.dumps(dict(program=spec["program"], status="NOT_ACQUIRED", error_type=type(exc).__name__)), flush=True)
    manifest = dict(scope="BENIGN_PUBLISHER_ARCHIVES_ONLY_NO_TRAINING_ADMISSION", created_utc=datetime.now(timezone.utc).isoformat(),
        target_profile_source="MATCHING_TARGETS_SAFE.zip aggregate results", archives=sorted(records, key=lambda r: r["software_lineage"]),
        acquisition_errors=errors, programs_planned=len(specs), archives_acquired=len(records),
        Windows_PE_parsing=False, PE_execution=False, malware_downloaded=False, restore=False, pack_unpack=False,
        new_matched_cohort_created=False, training_performed=False,
        notes=["Observed linker/Rich and packing status remain unknown until isolated VM audit",
               "Preserve software lineage; multiple executables/versions are not independent applications",
               "Do not substitute these acquisition counts for research sample counts"])
    save(args.out / "ACQUISITION_MANIFEST.json", json.dumps(manifest, indent=2).encode())
    print(json.dumps(dict(output=str(args.out), planned=len(specs), archives_acquired=len(records),
                          errors=len(errors), PE_parsed=False, training_performed=False)), flush=True)


if __name__ == "__main__":
    main()
