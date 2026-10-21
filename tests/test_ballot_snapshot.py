"""SR-10 tally reads one snapshot even when a legitimate append commits."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event, get_ident

from sqlalchemy import event

from ballot_credentials import accept_ballot_with_credential
from ballot_integrity import verified_candidate_ids_for_tally
from records import db
from test_ballot_credentials import NOW, issue, seed_voter
from test_credential_acceptance import PAYLOAD
from test_credential_concurrency import contention_app


def test_verification_does_not_mix_checkpoint_and_records_from_different_snapshots(contention_app):
    app, candidate_id, engine = contention_app
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    with app.app_context():
        first = issue()
        accept_ballot_with_credential(first, candidate_id, PAYLOAD, clock=lambda: NOW)
        seed_voter("voter-002")
        second = issue("voter-002")
        db.session.remove()

    state_read, writer_done = Event(), Event()
    reader_thread = get_ident()

    def wait_after_checkpoint(connection, cursor, statement, parameters, context, many):
        if (get_ident() == reader_thread and not state_read.is_set()
                and statement.upper().startswith("SELECT BALLOT_CHAIN_STATE")):
            state_read.set()
            assert writer_done.wait(timeout=15)

    def append_during_read():
        assert state_read.wait(timeout=15)
        try:
            with app.app_context():
                accept_ballot_with_credential(second, candidate_id, PAYLOAD, clock=lambda: NOW)
        finally:
            writer_done.set()

    event.listen(engine, "after_cursor_execute", wait_after_checkpoint)
    try:
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(append_during_read)
            with app.app_context():
                assert verified_candidate_ids_for_tally("election-2026", "Melbourne") == (candidate_id,)
            pending.result(timeout=20)
    finally:
        event.remove(engine, "after_cursor_execute", wait_after_checkpoint)
    with app.app_context():
        assert verified_candidate_ids_for_tally("election-2026", "Melbourne") == (candidate_id, candidate_id)
