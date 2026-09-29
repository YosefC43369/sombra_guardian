from __future__ import annotations
import io
import logging
import os
from dataclasses import dataclass
from typing import Iterator, Optional
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload
logger = logging.getLogger(__name__)
GOOGLE_DRIVE_SCOPES = (
    "https://www.googleapis.com/auth/drive.readonly",
)
@dataclass(frozen=True)
class DriveFile:
    file_id: str
    name: str
    mime_type: str
    size: Optional[int]
    modified_time: Optional[str]
    web_view_link: Optional[str]
class GoogleDriveSearch:
    """
    Google Drive read-only search layer.
    Important:
        files.list() is used for searching.
        No file content is downloaded during search.
    Content download is only performed when read_file() is explicitly
    called for a previously discovered file_id.
    """
    def __init__(
        self,
        credentials_path: Optional[str] = None,
        shared_drive_id: Optional[str] = None,
    ):
        self.credentials_path = (
            credentials_path
            or os.getenv("GOOGLE_DRIVE_CREDENTIALS")
        )
        self.shared_drive_id = (
            shared_drive_id
            or os.getenv("GOOGLE_DRIVE_SHARED_DRIVE_ID")
        )
        if not self.credentials_path:
            raise RuntimeError(
                "GOOGLE_DRIVE_CREDENTIALS is not configured"
            )
        if not os.path.isfile(self.credentials_path):
            raise FileNotFoundError(
                f"Google credentials not found: "
                f"{self.credentials_path}"
            )
        credentials = service_account.Credentials.from_service_account_file(
            self.credentials_path,
            scopes=list(GOOGLE_DRIVE_SCOPES),
        )
        self.service = build(
            "drive",
            "v3",
            credentials=credentials,
            cache_discovery=False,
        )
    def search(
        self,
        query: str,
        *,
        page_size: int = 50,
        include_trashed: bool = False,
    ) -> list[DriveFile]:
        """
        Search Google Drive without downloading file content.
        The query is searched against:
            - file name
            - indexed full text
        The actual file body is NOT downloaded here.
        """
        query = query.strip()
        if not query:
            return []
        escaped = query.replace("\\", "\\\\").replace("'", "\\'")
        drive_query = (
            "("
            f"name contains '{escaped}' "
            f"or fullText contains '{escaped}'"
            ")"
            f" and trashed = {str(include_trashed).lower()}"
        )
        fields = (
            "nextPageToken,"
            "files("
            "id,"
            "name,"
            "mimeType,"
            "size,"
            "modifiedTime,"
            "webViewLink"
            ")"
        )
        results: list[DriveFile] = []
        page_token: Optional[str] = None
        try:
            while True:
                request_kwargs = {
                    "q": drive_query,
                    "pageSize": max(1, min(page_size, 1000)),
                    "pageToken": page_token,
                    "fields": fields,
                    "orderBy": "modifiedTime desc",
                    "spaces": "drive",
                }
                if self.shared_drive_id:
                    request_kwargs.update(
                        {
                            "corpora": "drive",
                            "driveId": self.shared_drive_id,
                            "includeItemsFromAllDrives": True,
                            "supportsAllDrives": True,
                        }
                    )
                response = (
                    self.service.files()
                    .list(**request_kwargs)
                    .execute()
                )
                for item in response.get("files", []):
                    size = item.get("size")
                    results.append(
                        DriveFile(
                            file_id=item["id"],
                            name=item.get("name", ""),
                            mime_type=item.get(
                                "mimeType",
                                "application/octet-stream",
                            ),
                            size=int(size)
                            if size is not None
                            else None,
                            modified_time=item.get(
                                "modifiedTime"
                            ),
                            web_view_link=item.get(
                                "webViewLink"
                            ),
                        )
                    )
                page_token = response.get(
                    "nextPageToken"
                )
                if not page_token:
                    break
        except HttpError:
            logger.exception(
                "Google Drive search failed"
            )
            raise
        return results
    def get_metadata(
        self,
        file_id: str,
    ) -> DriveFile:
        """
        Retrieve metadata for one known file.
        No file content is downloaded.
        """
        request_kwargs = {
            "fileId": file_id,
            "fields": (
                "id,"
                "name,"
                "mimeType,"
                "size,"
                "modifiedTime,"
                "webViewLink"
            ),
        }
        if self.shared_drive_id:
            request_kwargs["supportsAllDrives"] = True
        item = (
            self.service.files()
            .get(**request_kwargs)
            .execute()
        )
        size = item.get("size")
        return DriveFile(
            file_id=item["id"],
            name=item.get("name", ""),
            mime_type=item.get(
                "mimeType",
                "application/octet-stream",
            ),
            size=int(size)
            if size is not None
            else None,
            modified_time=item.get(
                "modifiedTime"
            ),
            web_view_link=item.get(
                "webViewLink"
            ),
        )
    def read_file(
        self,
        file_id: str,
        *,
        max_bytes: int = 20 * 1024 * 1024,
    ) -> bytes:
        """
        Download content only after a file_id has been selected.
        This is deliberately separate from search().
        The complete file is kept in memory and is limited by max_bytes.
        """
        metadata = self.get_metadata(file_id)
        if metadata.size is not None:
            if metadata.size > max_bytes:
                raise ValueError(
                    f"File is too large: "
                    f"{metadata.size:,} bytes "
                    f"(limit {max_bytes:,})"
                )
        request = (
            self.service.files()
            .get(
                fileId=file_id,
                alt="media",
                supportsAllDrives=bool(
                    self.shared_drive_id
                ),
            )
        )
        buffer = io.BytesIO()
        downloader = MediaIoBaseDownload(
            buffer,
            request,
            chunksize=1024 * 1024,
        )
        done = False
        while not done:
            status, done = downloader.next_chunk()
            if status is not None:
                current_size = buffer.tell()
                if current_size > max_bytes:
                    raise ValueError(
                        "Downloaded content exceeded "
                        "configured size limit"
                    )
        return buffer.getvalue()
    def iter_file_lines(
        self,
        file_id: str,
        *,
        max_bytes: int = 20 * 1024 * 1024,
        encoding: str = "utf-8",
    ) -> Iterator[str]:
        """
        Read a selected Drive file as text lines.
        Search still happens first through search().
        This helper is intended for relatively small files.
        """
        content = self.read_file(
            file_id,
            max_bytes=max_bytes,
        )
        text = content.decode(
            encoding,
            errors="replace",
        )
        for line in text.splitlines():
            yield line