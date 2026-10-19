"""Hypothesis profiles. PR CI runs `--hypothesis-profile=ci` (SPEC-000 §Core engineering practices)."""

from hypothesis import settings

# Local default: fast feedback. The invariant floor of 2,000 examples is enforced by the `ci` profile.
settings.register_profile("dev", max_examples=100, deadline=None)
# PR CI: >= 2,000 examples per property with a fixed seed.
settings.register_profile("ci", max_examples=2000, derandomize=True, deadline=None, database=None, print_blob=True)
# Nightly (runs in the corpus repository): more examples, random seed.
settings.register_profile("nightly", max_examples=50000, deadline=None)
settings.load_profile("dev")
