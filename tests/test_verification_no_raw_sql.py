"""
SR-15: no SQL built from strings.

DB calls must use a fixed statement and let the driver bind values.
This test reads all project code and fails if SQL is made with
an f-string, %, + or .format().
"""

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SKIPPED_DIRS = {".venv", "venv", "tests", "__pycache__", ".git", "node_modules"}
SQL_WORDS = re.compile(
    r"\b(select|insert\s+into|update|delete\s+from|drop|alter|create)\b",
    re.IGNORECASE,
)
SQL_CALLS = {"execute", "text", "exec_driver_sql", "executescript"}


def project_files():
    for path in ROOT.rglob("*.py"):
        if not SKIPPED_DIRS & set(path.relative_to(ROOT).parts):
            yield path


def call_name(node):
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def literal_text(node):
    """All the text pieces inside an expression."""
    return " ".join(
        part.value
        for part in ast.walk(node)
        if isinstance(part, ast.Constant) and isinstance(part.value, str)
    )


def is_built_string(node):
    """True if the string is built while the code runs."""
    if isinstance(node, ast.JoinedStr):                    # f"..."
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True                                        # "..." % x, "..." + x
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"                     # "...".format(x)
    )


def risky_calls(source):
    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and call_name(node) in SQL_CALLS
            and node.args
            and is_built_string(node.args[0])
            and SQL_WORDS.search(literal_text(node.args[0]))
        ):
            found.append(node.lineno)
    return found


def test_project_builds_no_sql_from_strings():
    problems = []
    for path in project_files():
        for line in risky_calls(path.read_text(encoding="utf-8")):
            problems.append(f"{path.relative_to(ROOT)}:{line}")

    assert not problems, "SQL built from a string: " + ", ".join(problems)


# These tests check that the checker really catches bad patterns.

def test_checker_flags_fstring_sql():
    assert risky_calls('db.execute(f"SELECT * FROM t WHERE id={x}")')


def test_checker_flags_percent_sql():
    assert risky_calls('db.execute("DELETE FROM t WHERE id=%s" % x)')


def test_checker_flags_concatenated_sql():
    assert risky_calls('db.execute("SELECT * FROM t WHERE id=" + x)')


def test_checker_flags_format_sql():
    assert risky_calls('text("UPDATE t SET a={}".format(x))')


def test_checker_allows_fixed_and_bound_statements():
    assert not risky_calls('db.execute(text("SELECT 1 WHERE id = :id"), {"id": x})')
    assert not risky_calls("db.execute(select(User).where(User.id == x))")
