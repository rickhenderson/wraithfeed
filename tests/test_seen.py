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


def test_release_forgets_pending_but_not_finished(tmp_path):
    from store.seen import SeenStore

    with SeenStore(str(tmp_path / "db")) as store:
        store.mark_pending("https://a")
        store.release("https://a")
        assert not store.is_seen("https://a")

        store.mark_pending("https://b")
        store.mark_processed("https://b")
        store.release("https://b")
        assert store.is_seen("https://b")


def test_failed_url_is_retried_until_max_attempts(tmp_path):
    from store.seen import MAX_ATTEMPTS

    url = "https://example.com/flaky"
    with _store(tmp_path) as store:
        for _ in range(MAX_ATTEMPTS):
            assert store.should_process(url)
            store.mark_pending(url)
            store.mark_failed(url)
        assert not store.should_process(url)


def test_processed_url_is_never_reprocessed(tmp_path):
    url = "https://example.com/done"
    with _store(tmp_path) as store:
        store.mark_pending(url)
        store.mark_processed(url)
        assert not store.should_process(url)


def test_pending_left_by_crashed_run_counts_as_an_attempt(tmp_path):
    from store.seen import MAX_ATTEMPTS

    url = "https://example.com/crashes-the-run"
    with _store(tmp_path) as store:
        for _ in range(MAX_ATTEMPTS):
            assert store.should_process(url)
            store.mark_pending(url)  # run dies before mark_processed/mark_failed
        store.mark_pending(url)
        assert store.retry_count(url) == MAX_ATTEMPTS
        assert not store.should_process(url)


def test_release_of_a_retry_keeps_earlier_failures(tmp_path):
    url = "https://example.com/retry"
    with _store(tmp_path) as store:
        store.mark_pending(url)
        store.mark_failed(url)
        store.mark_pending(url)
        store.release(url)
        assert store.retry_count(url) == 1
        assert store.should_process(url)
