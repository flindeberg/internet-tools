"""
Tests of which routing data asnutils uses, and when it generates new.
Run from src/: python -m pytest ../tests
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import asnutils


def write_data(folder, name, dumped: datetime):
    header = "; IP-ASN32-DAT file\n; Original source: rib.{:}.bz2\n".format(
        dumped.strftime("%Y%m%d.%H%M")
    )
    (folder / (name + ".dat")).write_text(header + "1.0.0.0/24\t13335\n")
    (folder / (name + ".json")).write_text("{}")


def test_data_date(tmp_path, monkeypatch):
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    write_data(tmp_path, "pyasn", datetime(2026, 10, 10, 10, 0))
    assert asnutils.pyasn_data_date("pyasn") == datetime(2026, 10, 10, 10, 0)
    assert asnutils.pyasn_data_date("pyasn_local") is None


def test_data_date_with_path_in_header(tmp_path, monkeypatch):
    # as written by updatepyasnfiles.sh before it converted in the temporary folder
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    (tmp_path / "pyasn_local.dat").write_text(
        "; IP-ASN32-DAT file\n; Original source: /tmp/tmp.x/rib.20261010.1200.bz2\n"
    )
    (tmp_path / "pyasn_local.json").write_text("{}")
    assert asnutils.pyasn_data_date("pyasn_local") == datetime(2026, 10, 10, 12, 0)


def test_data_date_needs_names(tmp_path, monkeypatch):
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    write_data(tmp_path, "pyasn", datetime(2026, 10, 10, 10, 0))
    os.remove(tmp_path / "pyasn.json")
    assert asnutils.pyasn_data_date("pyasn") is None


def test_newest_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    write_data(tmp_path, "pyasn", datetime(2026, 10, 10, 10, 0))
    assert asnutils.pyasn_current_name() == "pyasn"
    # older local data (e.g. from before a git pull with a new snapshot)
    write_data(tmp_path, "pyasn_local", datetime(2026, 9, 1, 10, 0))
    assert asnutils.pyasn_current_name() == "pyasn"
    write_data(tmp_path, "pyasn_local", datetime(2026, 10, 20, 10, 0))
    assert asnutils.pyasn_current_name() == "pyasn_local"


def test_fresh_data_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    write_data(tmp_path, "pyasn", datetime.now() - timedelta(days=2))
    calls = []
    monkeypatch.setattr(asnutils.subprocess, "call", lambda *a, **k: calls.append(a))
    asnutils.ensure_fresh_pyasn_data(timedelta(days=7))
    assert calls == []


def test_old_data_is_regenerated_and_failure_is_survived(tmp_path, monkeypatch):
    monkeypatch.setattr(asnutils, "PYASN_DIR", str(tmp_path))
    write_data(tmp_path, "pyasn", datetime.now() - timedelta(days=30))
    calls = []

    def failing_call(cmd, env):
        calls.append(cmd)
        return 1

    monkeypatch.setattr(asnutils.subprocess, "call", failing_call)
    asnutils.ensure_fresh_pyasn_data(timedelta(days=7))
    assert calls == [[os.path.join(str(tmp_path), "updatepyasnfiles.sh")]]
