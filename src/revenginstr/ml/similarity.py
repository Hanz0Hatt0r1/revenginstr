"""Family-prototype cosine similarity for portable P-code classifiers.

This module is model-agnostic.  It compares TF-IDF documents against centroids
of label-pure function families.  Names, addresses, binary identity and strings
are not used.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def build_family_prototypes(vectorizer, texts: list[str], labels: list[str], families: list[str]):
    """Return L2-normalized sparse family centroids and family metadata."""
    import numpy as np
    from scipy import sparse
    from sklearn.preprocessing import normalize

    matrix = vectorizer.transform(texts)
    members: dict[str, list[int]] = defaultdict(list)
    for index, family_id in enumerate(families):
        members[family_id].append(index)

    prototype_rows = []
    prototype_labels: list[str] = []
    prototype_families: list[str] = []
    for family_id in sorted(members):
        indices = members[family_id]
        family_labels = {labels[index] for index in indices}
        if len(family_labels) != 1:
            continue
        centroid = sparse.csr_matrix(matrix[indices].mean(axis=0))
        centroid = normalize(centroid, norm="l2", copy=False)
        prototype_rows.append(centroid)
        prototype_labels.append(next(iter(family_labels)))
        prototype_families.append(family_id)

    prototypes = (
        sparse.vstack(prototype_rows, format="csr")
        if prototype_rows
        else sparse.csr_matrix((0, matrix.shape[1]), dtype=np.float64)
    )
    return {"matrix": prototypes, "labels": prototype_labels, "families": prototype_families}


def contrastive_family_scores(vectorizer, prototypes, texts: Iterable[str], predicted_labels: Iterable[str]) -> list[dict[str, object]]:
    """Score predicted-class structural support against the strongest competitor."""
    texts = list(texts)
    predicted_labels = list(predicted_labels)
    if len(texts) != len(predicted_labels):
        raise ValueError("text/prediction length mismatch")

    matrix = vectorizer.transform(texts)
    proto_matrix = prototypes["matrix"]
    proto_labels = list(prototypes["labels"])
    proto_families = list(prototypes["families"])
    class_indices: dict[str, list[int]] = defaultdict(list)
    for index, label in enumerate(proto_labels):
        class_indices[label].append(index)
    all_indices = list(range(len(proto_labels)))

    result: list[dict[str, object]] = []
    for row_index, predicted_label in enumerate(predicted_labels):
        predicted_indices = class_indices.get(predicted_label, [])
        competing_indices = [index for index in all_indices if proto_labels[index] != predicted_label]

        predicted_similarity = 0.0
        predicted_family = None
        if predicted_indices:
            sims = matrix[row_index].dot(proto_matrix[predicted_indices].T).toarray().ravel()
            if sims.size:
                local = int(sims.argmax())
                proto_index = predicted_indices[local]
                predicted_similarity = float(sims[local])
                predicted_family = proto_families[proto_index]

        competing_similarity = 0.0
        competing_family = None
        competing_label = None
        if competing_indices:
            sims = matrix[row_index].dot(proto_matrix[competing_indices].T).toarray().ravel()
            if sims.size:
                local = int(sims.argmax())
                proto_index = competing_indices[local]
                competing_similarity = float(sims[local])
                competing_family = proto_families[proto_index]
                competing_label = proto_labels[proto_index]

        result.append({
            "predicted_similarity": predicted_similarity,
            "predicted_family": predicted_family,
            "competing_similarity": competing_similarity,
            "competing_family": competing_family,
            "competing_label": competing_label,
            "contrast_margin": predicted_similarity - competing_similarity,
        })
    return result
