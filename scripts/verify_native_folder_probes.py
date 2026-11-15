"""Check the initial admission probes and the auxiliary catalogue-flush capture."""

import json

from native_filp import decode
from native_folder_stream import HTXF_HEADER_BYTES
from native_folder_upload_cases import catalogue_flush
from native_packet_evidence import reconcile
from native_wire_names import FIELD_TRANSFER_REFERENCE
from pcap_tcp import stream
from protocol_capture import verify_capture
from verify_native_cleanup import flow
from verify_native_core import require
from verify_native_folder_support import Corpus, Report, response
from verify_native_forks import fields

# The initial probes: three captures, of which exactly two fail admission.
INITIAL_PROBE_COUNT = 3
FAILED_PROBE_COUNT = 2


def check_boundary_probe(corpus: Corpus, report: Report, difference: Report) -> None:
    """Check the bytes of the probe whose boundary input differs from the corpus."""
    require(
        report["status"] == "failed" and not report["frames"],
        "Boundary-different probe reached folder protocol",
    )
    connect = report["events"][0]
    packets, client, endpoint = flow(report, connect["connection"], corpus.guest)
    require(
        stream(packets, client, endpoint).hex() == difference["guest_input_hex"]
        and stream(packets, endpoint, client).hex() == difference["guest_output_hex"],
        "Guest failed-admission bytes differ",
    )
    host_client, host_endpoint = (
        tuple(connect["local_address"]),
        tuple(connect["peer_address"]),
    )
    # This observed tuple was not reused in the bounded host corpus.
    require(
        stream(corpus.host, host_client, host_endpoint).hex()
        == report["streams"]["a"]["sent_hex"]
        == difference["host_sent_hex"],
        "Host failed-admission bytes differ",
    )
    require(
        stream(corpus.host, host_endpoint, host_client).hex()
        == report["streams"]["a"]["received_hex"]
        == difference["host_received_hex"]
        == "",
        "Unexpected host failed-admission output",
    )


def check_initial_probes(corpus: Corpus) -> list[Report]:
    """Check every initial admission probe and its inventory.

    Returns
    -------
    list[dict[str, typing.Any]]
        The case, status and error of each probe, in sorted order.
    """
    differences = json.loads(
        (corpus.directory / "initial-boundary-differences.json").read_text()
    )
    require(
        len(differences) == 1 and differences[0]["guest_input_hex"] == "",  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # == "" rejects a non-string value that "not" would accept
        "Initial boundary difference changed",
    )
    initial = []
    for path in sorted((corpus.directory / "initial-probes").rglob("report.json")):
        report = verify_capture(path.parent)
        require(
            report["driver_sha256"] in corpus.source_hashes,
            "Missing initial folder capture source",
        )
        name = str(path.parent.relative_to(corpus.directory))
        if name == differences[0]["case"]:
            check_boundary_probe(corpus, report, differences[0])
        else:
            reconcile(
                report,
                corpus.host,
                corpus.guest,
                {k: bytes.fromhex(v) for k, v in corpus.unread.get(name, {}).items()},
            )
        initial.append({
            "case": name,
            "status": report["status"],
            "error": report["error"],
        })
    require(
        len(initial) == INITIAL_PROBE_COUNT
        and sum(i["status"] == "failed" for i in initial) == FAILED_PROBE_COUNT,
        "Initial folder probe inventory differs",
    )
    return initial


def check_auxiliary(corpus: Corpus) -> None:
    """Check the catalogue-flush capture: its plan, its header and its finish."""
    auxiliary = verify_capture(corpus.directory / "auxiliary/folder-catalogue-flush")
    require(
        auxiliary["status"] == "completed"
        and auxiliary["driver_sha256"] in corpus.source_hashes,
        "Auxiliary finalization failed or source missing",
    )
    aux_plan = json.loads(
        (corpus.directory / "auxiliary/folder-catalogue-flush/plan.json").read_text()
    )
    aux_steps, aux_expectation = catalogue_flush()["folder-catalogue-flush"]
    require(
        aux_plan["steps"] == aux_steps and aux_plan["expectation"] == aux_expectation,
        "Auxiliary plan differs",
    )
    aux_packets = reconcile(auxiliary, corpus.host, corpus.guest)
    aux_values = fields(response(auxiliary))
    aux_sent = bytes.fromhex(auxiliary["streams"]["upload"]["sent_hex"])
    require(
        aux_sent[:8] == b"HTXF" + aux_values[FIELD_TRANSFER_REFERENCE]
        and int.from_bytes(aux_sent[8:12], "big") == len(aux_sent) - HTXF_HEADER_BYTES,
        "Auxiliary upload header differs",
    )
    aux_forks = decode(aux_sent[HTXF_HEADER_BYTES:])
    require(
        not aux_forks["DATA"]
        and not aux_forks["MACR"]
        and aux_packets["upload"]["guest_server_initiated_close"],
        "Auxiliary finalization bytes/close differ",
    )
