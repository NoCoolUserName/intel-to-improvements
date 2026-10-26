import diskcache


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
