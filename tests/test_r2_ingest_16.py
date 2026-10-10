from bastion.ingest.loader import ingest_file

TS = "2026-01-01T00:00:00Z"


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _check_one(evs):
    assert len(evs) == 1
    assert evs[0].host == "a" and evs[0].message == "hello"
    assert evs[0].ts.year == 2026 and evs[0].ts.month == 1


def test_semicolon_csv_is_sniffed(tmp_path):
    p = _write(tmp_path, "semi.csv", f"timestamp;host;message\n{TS};a;hello\n")
    _check_one(ingest_file(p))


def test_tab_csv_is_sniffed(tmp_path):
    p = _write(tmp_path, "tab.csv", f"timestamp\thost\tmessage\n{TS}\ta\thello\n")
    _check_one(ingest_file(p))


def test_pipe_csv_is_sniffed(tmp_path):
    p = _write(tmp_path, "pipe.csv", f"timestamp|host|message\n{TS}|a|hello\n")
    _check_one(ingest_file(p))


def test_excel_sep_line_is_honoured_and_dropped(tmp_path):
    p = _write(tmp_path, "sep.csv", f"sep=,\ntimestamp,host,message\n{TS},a,hello\n")
    _check_one(ingest_file(p))


def test_excel_sep_line_with_semicolon(tmp_path):
    p = _write(tmp_path, "sepsemi.csv", f"sep=;\ntimestamp;host;message\n{TS};a;hello\n")
    _check_one(ingest_file(p))


def test_comma_csv_with_semicolon_values_stays_comma(tmp_path):
    p = _write(tmp_path, "comma.csv",
               f"timestamp,host,message\n{TS},a,x;y;z\n{TS},b,p;q;r\n")
    evs = ingest_file(p)
    assert [(e.host, e.message) for e in evs] == [("a", "x;y;z"), ("b", "p;q;r")]


def test_undetectable_delimiter_falls_back_to_comma(tmp_path):
    p = _write(tmp_path, "one.csv", f"timestamp\n{TS}\n")
    evs = ingest_file(p)
    assert len(evs) == 1 and evs[0].ts.year == 2026
