"""Planner entries for rooms, moves, metadata, aliases, agreements and probes."""

import typing as typ

import native_room_cases as rooms
from native_agreement_cases import PHASES as AGREEMENT_PHASES
from native_agreement_cases import cleanup as agreement_cleanup
from native_agreement_cases import phase as agreement_phase
from native_agreement_cases import preflight as agreement_preflight
from native_agreement_cases import restore_stage as agreement_restore_stage
from native_agreement_cases import seed as agreement_seed
from native_agreement_cases import stages as agreement_stages
from native_alias_cases import cleanup as alias_cleanup
from native_alias_cases import create as alias_create
from native_alias_cases import damage as alias_damage
from native_alias_cases import downloads as alias_downloads
from native_alias_cases import information as alias_information
from native_alias_cases import seed as alias_seed
from native_alias_cases import supplementary as alias_supplementary
from native_auth_cases import cleanup as auth_cleanup
from native_auth_cases import guest_create as auth_guest_create
from native_auth_cases import lookup as auth_lookup
from native_auth_cases import reauthentication as auth_reauthentication
from native_auth_cases import seed as auth_seed
from native_auth_cases import states as auth_states
from native_correlation_cases import correlation
from native_framing_cases import framing
from native_htxf_cases import htxf
from native_login_extras_cases import NAMES as LOGIN_EXTRA_NAMES
from native_login_extras_cases import configured as login_extras_configured
from native_login_extras_cases import downloads as login_extras_downloads
from native_login_extras_cases import lifetime as login_extras_lifetime
from native_login_extras_cases import version_presence
from native_metadata_cases import account_cleanup as metadata_account_cleanup
from native_metadata_cases import boundaries as metadata_boundaries
from native_metadata_cases import cleanup as metadata_cleanup
from native_metadata_cases import combined_empty as metadata_combined_empty
from native_metadata_cases import finalization as metadata_final
from native_metadata_cases import mutations as metadata_mutations
from native_metadata_cases import preflight as metadata_preflight
from native_metadata_cases import seed as metadata_seed
from native_mkdir_cases import cleanup as mkdir_cleanup
from native_mkdir_cases import creation as mkdir_creation
from native_mkdir_cases import empty_root as mkdir_empty_root
from native_mkdir_cases import finalization as mkdir_final
from native_mkdir_cases import seed as mkdir_seed
from native_move_cases import cleanup as move_cleanup
from native_move_cases import deletions as move_deletions
from native_move_cases import finalization as move_final
from native_move_cases import moves as move_moves
from native_move_cases import preflight as move_preflight
from native_move_cases import seed as move_seed

if typ.TYPE_CHECKING:
    from pathlib import Path

    from prepare_native_cases_inputs import Entry, Inputs


def entries(inputs: Inputs) -> dict[str, Entry]:
    """Return the entry of each record suite, keyed by suite name.

    Parameters
    ----------
    inputs : Inputs
        The command-line values; only the original agreement is read, and only
        by ``agreement-restore-stage``.

    Returns
    -------
    dict[str, Entry]
        One entry per record suite, each a function of no arguments.
    """
    return {
        "rooms": rooms.suites,
        "move-preflight": move_preflight,
        "move-seed": move_seed,
        "move-moves": move_moves,
        "move-deletions": move_deletions,
        "move-final": move_final,
        "move-cleanup": move_cleanup,
        "metadata-preflight": metadata_preflight,
        "metadata-combined-empty": metadata_combined_empty,
        "metadata-account-cleanup": metadata_account_cleanup,
        "metadata-boundaries": metadata_boundaries,
        "metadata-final": metadata_final,
        "metadata-seed": metadata_seed,
        "metadata-mutations": metadata_mutations,
        "metadata-cleanup": metadata_cleanup,
        "alias-cleanup": alias_cleanup,
        "alias-supplementary": alias_supplementary,
        "alias-damage": alias_damage,
        "alias-seed": alias_seed,
        "alias-create": alias_create,
        "alias-info": alias_information,
        "alias-download": alias_downloads,
        "mkdir-root-empty": mkdir_empty_root,
        "mkdir-final": mkdir_final,
        "mkdir-cleanup": mkdir_cleanup,
        "mkdir-seed": mkdir_seed,
        "mkdir-create": mkdir_creation,
        "login-version-presence": version_presence,
        "login-extras-lifetime": login_extras_lifetime,
        "login-extras-downloads": login_extras_downloads,
        **{
            "login-extras-" + name: lambda name=name: login_extras_configured(name)
            for name in LOGIN_EXTRA_NAMES
        },
        "agreement-preflight": agreement_preflight,
        "agreement-seed": agreement_seed,
        "agreement-stages": agreement_stages,
        "agreement-restore-stage": lambda: agreement_restore_stage(
            typ.cast("Path", inputs.original_agreement).read_bytes()
        ),
        "agreement-cleanup": agreement_cleanup,
        **{
            "agreement-" + name: lambda name=name: agreement_phase(name)
            for name in AGREEMENT_PHASES
        },
        "auth-seed": auth_seed,
        "auth-lookup": auth_lookup,
        "auth-missing-guest": lambda: auth_lookup(missing_guest=True),
        "auth-guest-create": auth_guest_create,
        "auth-states": auth_states,
        "auth-reauthentication": auth_reauthentication,
        "auth-cleanup": auth_cleanup,
        "correlation": correlation,
        "htxf": htxf,
        "framing": framing,
    }
