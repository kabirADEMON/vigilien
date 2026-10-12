import json

from vigilien.cli import main


def test_sortie_json_et_code_de_sortie(capsys):
    code = main(["--hors-ligne", "--json", "http://mtn.bj.verification-compte.xyz/momo/login", "https://www.mtn.bj"])
    data = json.loads(capsys.readouterr().out)
    assert [d["verdict"] for d in data] == ["élevé", "faible"]
    assert code == 2  # le pire lien décide


def test_sortie_texte(capsys):
    assert main(["--hors-ligne", "https://www.mtn.bj"]) == 0
    out = capsys.readouterr().out
    assert "Risque faible : 0/100" in out


def test_lien_illisible(capsys):
    assert main(["--hors-ligne", "http://"]) == 3
    assert "Lien illisible" in capsys.readouterr().err
