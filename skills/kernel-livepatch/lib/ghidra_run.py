"""Helper for invoking Ghidra's analyzeHeadless (flatpak or local install)."""

import os
import subprocess
from pathlib import Path

FLATPAK_APP_ID = 'org.ghidra_sre.Ghidra'


def ghidra_run(project_dir: str, project_name: str, headless_args: list,
               ghidra: str = '', quiet: bool = False) -> None:
    """Run analyzeHeadless with the given project and extra args.

    Args:
        project_dir:   Ghidra project directory.
        project_name:  Ghidra project name.
        headless_args: Extra args passed after project_dir and project_name
                       (e.g. ['-import', file, ...] or ['-process', ...]).
        ghidra:        Path to GHIDRA_HOME, or '' to use the flatpak.
        quiet:         Suppress all Ghidra output (stdout/stderr).
    """
    if not ghidra:
        ghidra = os.environ.get('GHIDRA_HOME', '')

    base = [str(project_dir), str(project_name)] + [str(a) for a in headless_args]

    if ghidra:
        cmd = [str(Path(ghidra) / 'support' / 'analyzeHeadless')] + base
    else:
        cmd = [
            'flatpak', 'run',
            '--command=/app/lib/ghidra/support/analyzeHeadless',
            FLATPAK_APP_ID,
        ] + base

    print('Running:', ' '.join(cmd))

    devnull = subprocess.DEVNULL if quiet else None
    subprocess.run(cmd, check=True, stdout=devnull, stderr=devnull)
