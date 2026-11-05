import diskcache
from iti import detection


def test_every_bundled_sigma_conversion_avoids_diskcache(monkeypatch):
    """A new bundled rule must not silently introduce the unsafe cache path."""
    def reject_cache(*args, **kwargs):
        raise AssertionError("Bundled Sigma conversion must not open diskcache")

    monkeypatch.setattr(diskcache.Cache, "__init__", reject_cache)
    rows = detection.catalog()
    assert rows
    for _, raw, _ in rows:
        detection.convert(raw, {
            "Image": "process_path",
            "CommandLine": "command_line",
            "OriginalFileName": "original_name",
        })


def test_local_sigma_workflow_does_not_open_diskcache(service, monkeypatch):
    """The unpatched diskcache path must stay unused by local catalog workflows."""
    def reject_cache(*args, **kwargs):
        raise AssertionError("Local Sigma workflows must not open a diskcache cache")

    monkeypatch.setattr(diskcache.Cache, "__init__", reject_cache)
    job = service.submit(
        "fictional-bank", "windows-ad", "replay", "case", "activemq-derived",
        background=False,
    )
    assert job["state"] == "complete", job["data"].get("error")
    assessment = service.store.get("assessment", job["data"]["assessment_id"])
    assert assessment["candidates"]
    assert all(candidate["conversion_supported"] for candidate in assessment["candidates"])
    package = service.generate(assessment["id"], "fictional-bank")
    assert package["candidates"]
