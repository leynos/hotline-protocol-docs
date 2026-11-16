"""Characterize ``native_ban_control_cases`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The five plans
are pinned by fingerprints of their exact steps, and the plans written to a
directory by their digests. The order of the refusals of ``write_plans`` is
pinned by pairs of faults.
"""

import hashlib
import json
import typing as typ

import native_ban_control_cases as cases
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path

A7_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
PLAN_STEPS = {"readiness": 18, "guard": 10, "seed": 12, "ban": 32, "probe": 6}
PLAN_FINGERPRINTS = {
    "readiness": "669b539a4cd83c34b3f20f5422fb92d61e413184cd64b634260d506f2f998214",
    "guard": "248991d608141381d5e13f6e5b3031c16800105475d164c8860e9a5c39d1c523",
    "seed": "8ec972d0af77f678c61b2ef3f48f98ea13782ab32f9e5c9f6bd2df3b48c50597",
    "ban": "ee73fc1dac4ee070919ceaa43ccf659bc918398b0d2cdd1eb1229c435aab39bd",
    "probe": "1bdd0c17f823c9d5a8d325b763536249db89e525856dc0657c7fd5d3b991ca89",
}
EXCHANGE_FINGERPRINTS = [
    "0eb1613543b96ab331fb13d9cb8d0652d2d3a204c5ce20f0607465672bad961b",
    "fd74ad7090f28dbd5138e4f49266133e338f5f76eeaa74853cec29ab21a34c5b",
]
WRITTEN_DIGESTS = {
    "readiness": "fd6060c2ebf05d8d4e7d0248234d38bad5898a965f6e047a08a833ca94eb589b",
    "guard": "ffae28f18c0207ad619cf1657b3bd963844d03d9da0ef3336f1fa8853d3b36ad",
    "seed": "223fd5a764ba3c112bf4aa544b7a58524bb0255b0e8a07200a0164fbda2178bc",
    "ban": "108d025362c9281645dfcf147d950d04a16de3f8db64f2bd3de3450cb6ca6de6",
    "probe": "17c31d1988703d2daafeca43eb8d49fc374677ba44295ae7f13995b045cc9692",
}
ENVIRONMENT = {"source_a7_sha256": A7_SHA, "emulator_pid": 5}
PORT_MESSAGE = r"^Control endpoint must be an owned lab port$"
SOURCE_MESSAGE = r"^Original A7 source-plan hash differs$"
LOWEST_PORT = 1024
HIGHEST_PORT = 65534


def fingerprint(value: object) -> str:
    """Hash the JSON text of a value, keys in their existing order.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


class ConstantTests:
    """The constants that the control scripts and the verifiers import."""

    def test_the_account_and_file_constants_are_unchanged(self) -> None:
        """The owned key, password, target name, zero access and file name."""
        assert cases.KEY == b"m-ban52-only", "expected the owned key"
        assert cases.PASSWORD == b"ban52-pass", "expected the password"
        assert cases.NAME == b"Ban52 Target", "expected the target name"
        assert cases.ZERO.hex() == "00" * 8, "expected the zero bitmap"
        assert cases.FILE == b"mothra-race-fixture", "expected the file name"
        assert cases.A7_SHA == A7_SHA, "expected the A7 source-plan hash"


class PlanTests:
    """The five plans, pinned by fingerprint."""

    def test_the_plans_are_in_order_with_their_step_counts(self) -> None:
        """Readiness, guard, seed, ban and probe."""
        built = cases.plans()
        assert list(built) == list(PLAN_STEPS), "expected the plan order"
        assert {n: len(steps) for n, steps in built.items()} == PLAN_STEPS, "counts"

    @pytest.mark.parametrize("name", sorted(PLAN_FINGERPRINTS))
    def test_each_plan_is_unchanged(self, name: str) -> None:
        """Every step of the plan, byte for byte."""
        assert fingerprint(cases.plans()[name]) == PLAN_FINGERPRINTS[name], name

    def test_an_exchange_is_a_request_and_its_reply(self) -> None:
        """A send and a matched read, with or without fields."""
        steps = cases.exchange(348, 10, [])
        assert [step["op"] for step in steps] == ["send", "read_frame"], "op order"
        assert fingerprint(steps) == EXCHANGE_FINGERPRINTS[0], "expected same steps"
        with_field = cases.exchange(200, 11, [(202, b"\0\0")])
        assert fingerprint(with_field) == EXCHANGE_FINGERPRINTS[1], "expected same"


class WritePlansTests:
    """``write_plans`` checks the port and the source hash, then writes."""

    def test_five_plans_are_written_and_their_digests_returned(
        self, tmp_path: Path
    ) -> None:
        """The digest of each file's bytes, in plan order."""
        written = cases.write_plans(tmp_path / "plans", ENVIRONMENT, 15750)
        assert written == WRITTEN_DIGESTS, "expected the recorded digests"
        for name, digest in written.items():
            data = (tmp_path / "plans" / f"{name}.json").read_bytes()
            assert hashlib.sha256(data).hexdigest() == digest, name

    def test_a_plan_embeds_the_environment_endpoint_and_expectation(
        self, tmp_path: Path
    ) -> None:
        """The environment gains the fixture profile; the endpoint is the port."""
        cases.write_plans(tmp_path / "plans", ENVIRONMENT, 15750)
        plan = json.loads((tmp_path / "plans/ban.json").read_text())
        assert plan["environment"] == {
            **ENVIRONMENT,
            "fixture_profile": "control-only",
            "full_file_baseline": "not_exercised",
        }, "expected the control-only environment"
        endpoint = {"control": {"host": "127.0.0.1", "port": 15750}}
        assert plan["endpoints"] == endpoint, "expected the control endpoint"
        assert plan["expectation"] == {
            "case": "ban",
            "owned_key_hex": cases.KEY.hex(),
        }, "expected the case and key"
        assert plan["gap_ids"] == ["GAP-044"], "expected the gap"
        assert plan["operator"] == "C52 isolated ban-control operator", "operator"

    @pytest.mark.parametrize("port", [15500, 15501, LOWEST_PORT - 1, HIGHEST_PORT + 1])
    def test_a_port_outside_the_owned_range_is_refused_before_the_directory(
        self, tmp_path: Path, port: int
    ) -> None:
        """The two primary bridge ports and anything outside 1024 to 65534."""
        with pytest.raises(ValueError, match=PORT_MESSAGE):
            cases.write_plans(tmp_path / "plans", ENVIRONMENT, port)
        assert not (tmp_path / "plans").exists(), "expected no directory"

    @pytest.mark.parametrize("port", [LOWEST_PORT, HIGHEST_PORT])
    def test_the_ends_of_the_owned_range_are_accepted(
        self, tmp_path: Path, port: int
    ) -> None:
        """Both ends are inclusive."""
        written = cases.write_plans(tmp_path / "plans", ENVIRONMENT, port)
        assert list(written) == list(PLAN_STEPS), "expected five plans"

    @pytest.mark.parametrize("environment", [{}, {"source_a7_sha256": "x"}])
    def test_a_different_source_hash_is_refused_before_the_directory(
        self, tmp_path: Path, environment: dict[str, str]
    ) -> None:
        """A missing or different A7 source-plan hash."""
        with pytest.raises(ValueError, match=SOURCE_MESSAGE):
            cases.write_plans(tmp_path / "plans", environment, 15750)
        assert not (tmp_path / "plans").exists(), "expected no directory"

    def test_the_port_is_checked_before_the_source_hash(self, tmp_path: Path) -> None:
        """Both faults at once end with the port."""
        with pytest.raises(ValueError, match=PORT_MESSAGE):
            cases.write_plans(tmp_path / "plans", {}, 15500)

    def test_an_existing_directory_is_refused_after_both_checks(
        self, tmp_path: Path
    ) -> None:
        """The directory is made exclusively, so an existing one is an error."""
        (tmp_path / "plans").mkdir()
        with pytest.raises(FileExistsError):
            cases.write_plans(tmp_path / "plans", ENVIRONMENT, 15750)
        with pytest.raises(ValueError, match=SOURCE_MESSAGE):
            cases.write_plans(tmp_path / "plans", {}, 15750)
        with pytest.raises(ValueError, match=PORT_MESSAGE):
            cases.write_plans(tmp_path / "plans", {}, 15500)
        assert not list((tmp_path / "plans").iterdir()), "expected it untouched"
