"""Tests critiques RAG : regression U+2028/U+2029 et structure /ai/rag/stats.

Regression U+2028/U+2029 : certains docs CVE/MITRE contiennent les separateurs
Unicode LINE SEPARATOR (U+2028) / PARAGRAPH SEPARATOR (U+2029). Si on utilise
str.splitlines() sur docs.jsonl, ces caracteres coupent une ligne JSON au
milieu d'une string -> JSONDecodeError silencieux -> l'index etait amputee.
Le fix : lire le fichier ligne-a-ligne (iterator natif respecte \n seulement)
et skipper les lignes JSON invalides.

test_rag_stats_shape verrouille la structure retournee par /ai/rag/stats
pour que les consommateurs (frontend) ne cassent pas si un dev modifie stats().
"""

from __future__ import annotations

import json

import pytest


def test_faiss_rag_load_handles_unicode_line_separators(tmp_path):
    """FaissRAG._load doit survivre a des docs contenant U+2028/U+2029.

    On ecrit 3 docs dans docs.jsonl dont un avec U+2028 et U+2029 inseres
    dans le champ text. Le load ne doit rien crasher et doit retourner
    les 3 docs (les chars unicode restent dans le text apres parse JSON).
    """
    from apps.api.ai.rag import FaissRAG

    index_dir = tmp_path / "rag"
    index_dir.mkdir()
    docs_path = index_dir / "docs.jsonl"

    docs = [
        {"id": "a", "source": "mitre", "text": "hello world", "metadata": {}},
        {
            "id": "b",
            "source": "nvd",
            # U+2028 LINE SEPARATOR + U+2029 PARAGRAPH SEPARATOR dans le texte
            "text": "CVE-XXXX\u2028second line\u2029third line",
            "metadata": {"cvss": 7.5},
        },
        {"id": "c", "source": "sigma", "text": "rule detection", "metadata": {}},
    ]
    # Ecriture manuelle : on veut un \n comme unique separateur de ligne,
    # meme si json.dumps produit des caracteres U+2028 dans le text serialise
    # (ensure_ascii=False).
    with docs_path.open("w", encoding="utf-8", newline="") as fh:
        for d in docs:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")

    # _load est appele dans __init__
    rag = FaissRAG(index_dir=str(index_dir))

    assert len(rag._docs) == 3, "Les 3 docs doivent etre charges malgre U+2028/U+2029"
    ids = {d["id"] for d in rag._docs}
    assert ids == {"a", "b", "c"}
    # Le doc avec U+2028 conserve bien ces chars dans son text
    doc_b = next(d for d in rag._docs if d["id"] == "b")
    assert "\u2028" in doc_b["text"]
    assert "\u2029" in doc_b["text"]


@pytest.mark.integration
def test_rag_stats_endpoint_shape(api_client, tmp_path, monkeypatch):
    """GET /ai/rag/stats retourne les cles attendues par le frontend.

    Contrat : {total_docs, by_source, last_updated, index_size_mb,
               index_dir, embedding_model, embedding_dim, sources_manifest}
    """
    # On force un index dir vide et isole pour ne pas depender de l'etat
    # prod de l'index FAISS.
    from apps.api.ai import rag as rag_mod

    monkeypatch.setattr(rag_mod, "_rag_instance", None)
    monkeypatch.setattr(rag_mod, "DEFAULT_INDEX_DIR", str(tmp_path / "rag_test"))

    r = api_client.get("/ai/rag/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    expected_keys = {
        "total_docs",
        "by_source",
        "last_updated",
        "index_size_mb",
        "index_dir",
        "embedding_model",
        "embedding_dim",
        "sources_manifest",
    }
    missing = expected_keys - set(body.keys())
    assert not missing, f"Cles manquantes dans /ai/rag/stats: {missing}"
    assert isinstance(body["total_docs"], int)
    assert isinstance(body["by_source"], dict)
    assert isinstance(body["embedding_dim"], int)
