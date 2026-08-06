from store.seen import RunStats, STATUS_FAILED, STATUS_PROCESSED, SeenStore


def _store(tmp_path):
    return SeenStore(str(tmp_path / "wraithfeed.db"))


def test_new_url_not_seen(tmp_path):
    with _store(tmp_path) as store:
        assert store.is_seen("https://example.com/article") is False


def test_mark_pending_then_seen(tmp_path):
    url = "https://example.com/article"
    with _store(tmp_path) as store:
        store.mark_pending(url)
        assert store.is_seen(url) is True


def test_mark_processed_updates_status(tmp_path):
    url = "https://example.com/article"
    with _store(tmp_path) as store:
        store.mark_pending(url)
        store.mark_processed(url)
        row = store.conn.execute(
            "SELECT status FROM seen WHERE url = ?", (url,)
        ).fetchone()
        assert row[0] == STATUS_PROCESSED


def test_mark_failed_increments_retry_count(tmp_path):
    url = "https://example.com/article"
    with _store(tmp_path) as store:
        store.mark_pending(url)
        store.mark_failed(url)
        store.mark_failed(url)
        assert store.retry_count(url) == 2
        row = store.conn.execute(
            "SELECT status FROM seen WHERE url = ?", (url,)
        ).fetchone()
        assert row[0] == STATUS_FAILED


def test_persists_across_reopen(tmp_path):
    db_path = str(tmp_path / "wraithfeed.db")
    url = "https://example.com/article"

    with SeenStore(db_path) as store:
        store.mark_pending(url)

    with SeenStore(db_path) as store:
        assert store.is_seen(url) is True


def test_log_run_records_stats(tmp_path):
    with _store(tmp_path) as store:
        store.log_run(RunStats(source="unit42", collected=5, processed=4, failed=1))
        row = store.conn.execute(
            "SELECT source, collected, processed, failed FROM run_log"
        ).fetchone()
        assert row == ("unit42", 5, 4, 1)
