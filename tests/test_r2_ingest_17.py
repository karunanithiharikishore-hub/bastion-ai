from bastion.ingest.loader import ingest_file


def test_stray_leading_quote_does_not_swallow_following_rows(tmp_path, capsys):
    p = tmp_path / "cmd.csv"
    p.write_text('timestamp,host,message\n'
                 '2026-01-01T00:00:00Z,a,"unterminated quote\n'
                 '2026-01-01T00:01:00Z,b,second\n'
                 '2026-01-01T00:02:00Z,c,third\n')
    evs = ingest_file(str(p))
    assert len(evs) == 3
    assert {e.host for e in evs} == {"a", "b", "c"}
    assert "unbalanced quote" in capsys.readouterr().err


def test_legit_multiline_quoted_field_still_parses(tmp_path, capsys):
    p = tmp_path / "msgs.csv"
    p.write_text('timestamp,host,message\n'
                 '2026-01-01T00:00:00Z,a,"line one\nline two, with comma\nline three"\n'
                 '2026-01-01T00:01:00Z,b,plain\n')
    evs = ingest_file(str(p))
    assert len(evs) == 2
    assert evs[0].host == "a" and "line three" in evs[0].raw["message"]
    assert "unbalanced" not in capsys.readouterr().err
