from importlib.resources import files
from types import SimpleNamespace

from streamlit.testing.v1 import AppTest

from soc_gpt import es_client


def test_console_starts_offline_and_loads_bundled_rules(monkeypatch):
    monkeypatch.setattr(es_client, "get_client", lambda: SimpleNamespace(ping=lambda: False))
    app = AppTest.from_file(str(files("soc_gpt").joinpath("ui/app.py")))
    app.run(timeout=15)
    assert not app.exception
    assert app.title[0].value == "SOC-GPT — AI-Augmented Triage Console"

    app.sidebar.radio[0].set_value("Sigma Rules").run()
    assert not app.exception
    app.button[0].click().run()
    assert not app.exception
    assert len(app.session_state["loaded_rules"]) == 4
