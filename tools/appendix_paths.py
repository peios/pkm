"""Source and companion-document paths shared by the TRM generators."""

import os
from pathlib import Path


# Use the checkout containing this module, irrespective of its directory name
# or the caller's working directory. A sibling called pkm may be another tree.
PKM = Path(__file__).resolve().parents[1]
_configured_learn = os.environ.get("PKM_LEARN_ROOT")
LEARN = (
    Path(_configured_learn).expanduser().resolve()
    if _configured_learn
    else PKM.parent / "learn"
)

if _configured_learn is not None and (
    not _configured_learn or not (LEARN / "peios.product").is_dir()
):
    raise SystemExit(
        "PKM_LEARN_ROOT must name a learn checkout containing peios.product: "
        + repr(_configured_learn)
    )


def learn_is_absent():
    """Standalone kernel checkouts need no optional sibling documentation.

    An explicitly configured companion was validated above and never skips.
    A present learn checkout with a missing appendix must fail --check or have
    that appendix generated, rather than silently skipping a drift check.
    """
    return not (LEARN / "peios.product").is_dir()
