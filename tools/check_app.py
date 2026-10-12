"""Check a built Sequent.app, or the Linux helper, decodes the CDJs as it should.

The app's --selftest decodes captured CDJ status packets and prints two
messages it builds. tools/fixtures/selftest.expected holds what that must be:
the output once the app and the Python helper it replaced (djlink.py, in git
history) agreed byte for byte, and the app had run with real CDJs. Matching
it shows the app as built, not only as written, still reads the players and
speaks to them correctly. JSON is compared parsed, so harmless differences
in how numbers are printed don't fail it.

The release pipeline runs this on every build; run it locally with

    make app && python3 tools/check_app.py build/Sequent.app

or, for the Linux helper, give the program itself:

    python3 tools/check_app.py helper/linux/sequent

If the decoding changes on purpose, regenerate the expected output from a
build that has been tried with real CDJs, and say so in the commit.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
FIXTURES = sorted((HERE / "fixtures").glob("status-deck*.bin"))
EXPECTED = (HERE / "fixtures" / "selftest.expected").read_text().splitlines()
STATUS_PORT = 50002


def same(got, want):
    try:
        return json.loads(got) == json.loads(want)
    except ValueError:
        return got == want


def main(app):
    binary = pathlib.Path(app)
    if binary.is_dir():
        binary = binary / "Contents" / "MacOS" / "Sequent"
    args = [f"{STATUS_PORT}:{f}" for f in FIXTURES]
    out = subprocess.run([str(binary), "--selftest", *args], capture_output=True, text=True, check=True, timeout=30).stdout.splitlines()
    if len(out) != len(EXPECTED):
        sys.exit(f"expected {len(EXPECTED)} lines from --selftest, got {len(out)}")
    names = [f.name for f in FIXTURES] + ["dbserver message", "announcement", "origin check"]
    failures = [f"{name}:\n  got  {got}\n  want {want}" for name, got, want in zip(names, out, EXPECTED) if not same(got, want)]
    if failures:
        sys.exit("\n".join(failures))
    print(f"ok: {len(FIXTURES)} status packets decoded and both messages built as expected")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/Sequent.app")
