from __future__ import annotations

from revenginstr.receiver.infer import infer


def test_receiver_inference_resolves_unique_direct_type() -> None:
    receiver_rows = [{
        "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
        "source_id": "sample.exe:1000",
        "call_index": "0",
        "call_address": "1010",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "class Game::Vehicle",
        "receiver_type_name": "Vehicle *",
        "receiver_type_display": "Game::Vehicle *",
        "receiver_storage_kind": "register",
        "flow_type_node_count": "1",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [{
        "format": "consumer.catalog/7",
        "class_name": "Game::Vehicle",
        "receiver_vtable_id": "vtbl:vehicle",
    }]
    rows = infer(receiver_rows, catalog)
    assert len(rows) == 1
    row = rows[0]
    assert row["format"] == "REVENGINSTR.ReceiverInference/1"
    assert row["status"] == "resolved_unique_vtable"
    assert row["class_name"] == "Game::Vehicle"
    assert row["receiver_vtable_id"] == "vtbl:vehicle"
    assert row["affects_routing"] is False
    assert row["dispatch_slot_offset"] is None


def test_receiver_inference_uses_unique_terminal_name() -> None:
    receiver_rows = [{
        "format": "legacy.receiver/2",
        "source_id": "sample:2000",
        "call_index": "1",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "struct Vehicle",
        "receiver_storage_kind": "unique",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [{"class_name": "Namespace::Vehicle", "receiver_vtable_id": "v1"}]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "resolved_unique_vtable"
    assert row["class_match_kind"] == "unique_terminal_class_name"


def test_receiver_inference_rejects_ambiguous_terminal_name() -> None:
    receiver_rows = [{
        "source_id": "sample:3000",
        "call_index": "0",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "Vehicle",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [
        {"class_name": "A::Vehicle", "receiver_vtable_id": "a"},
        {"class_name": "B::Vehicle", "receiver_vtable_id": "b"},
    ]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "unresolved_receiver_class"
    assert row["receiver_vtable_id"] is None


def test_receiver_inference_detects_multi_vtable_class() -> None:
    receiver_rows = [{
        "source_id": "sample:4000",
        "call_index": "0",
        "receiver_pointer_depth": "1",
        "pointee_type_display": "Game::Vehicle",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [
        {"class_name": "Game::Vehicle", "receiver_vtable_id": "v1"},
        {"class_name": "Game::Vehicle", "receiver_vtable_id": "v2"},
    ]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "ambiguous_class_vtable"
    assert row["candidate_receiver_vtable_ids"] == ["v1", "v2"]
