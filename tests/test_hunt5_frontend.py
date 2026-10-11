from pathlib import Path

S = Path(__file__).resolve().parents[1] / "src/bastion/web/static"
rd = lambda n: (S / n).read_text()


def test_menu_button_and_toggle():
    for page, js in (("index.html", "app.js"), ("runs.html", "runs.js")):
        h = rd(page)
        assert 'id="menu-btn"' in h and 'aria-expanded="false"' in h and 'aria-controls="topnav"' in h
        assert 'id="topnav"' in h
        j = rd(js)
        assert 'getElementById("menu-btn")' in j and "aria-expanded" in j and "addEventListener" in j


def test_css_rules():
    c = rd("styles.css")
    assert ".topbar.open .topnav" in c and ".menu-btn" in c
    assert "white-space: nowrap" in c and "@media (max-width: 1480px)" in c
    assert "no-repeat local" in rd("runs.html")
