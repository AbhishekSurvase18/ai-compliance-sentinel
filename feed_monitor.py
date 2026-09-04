"""Bounded polling of approved official regulatory publication feeds."""

from dataclasses import dataclass
from urllib.request import Request, urlopen

from regulatory import OFFICIAL_FEEDS


@dataclass(frozen=True)
class FeedSnapshot:
	source: str
	url: str
	status: str
	content: str
	error: str | None = None


def fetch_official_feed(source: str, timeout_seconds: float = 5.0, max_bytes: int = 1_000_000) -> FeedSnapshot:
	url = OFFICIAL_FEEDS.get(source)
	if not url:
		return FeedSnapshot(source, "", "rejected", "", "source is not on the approved official-feed allowlist")
	request = Request(url, headers={"User-Agent": "ComplianceSentinel/1.0"})
	try:
		with urlopen(request, timeout=timeout_seconds) as response:
			content = response.read(max_bytes + 1)
	except Exception as error:
		return FeedSnapshot(source, url, "unavailable", "", str(error))
	if len(content) > max_bytes:
		return FeedSnapshot(source, url, "rejected", "", "feed exceeded maximum size")
	return FeedSnapshot(source, url, "fetched", content.decode("utf-8", errors="replace"))
