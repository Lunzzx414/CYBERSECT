import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_DATABASE_BYTES = 16 * 1024 * 1024


def _quoted_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _analyze_connection(connection: sqlite3.Connection) -> Dict[str, Any]:
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        schema_objects = connection.execute(
            """
            SELECT type, name
            FROM sqlite_schema
            WHERE type IN ('table', 'view')
              AND name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            LIMIT 501
            """
        ).fetchall()
        if len(schema_objects) > 500:
            raise ValueError("Database has more than 500 tables and views.")

        tables: List[Dict[str, Any]] = []
        findings: List[Dict[str, str]] = []
        column_count = 0

        for object_type, name in schema_objects:
            quoted_name = _quoted_identifier(name)
            columns = connection.execute(
                f"PRAGMA table_info({quoted_name})"
            ).fetchall()
            column_count += len(columns)
            primary_key_columns = [
                column[1]
                for column in sorted(columns, key=lambda item: item[5])
                if column[5] > 0
            ]

            tables.append(
                {
                    "name": name,
                    "type": object_type,
                    "columns": [
                        {
                            "name": column[1],
                            "type": column[2] or "unspecified",
                            "nullable": not bool(column[3]) and column[5] == 0,
                            "primary_key_position": column[5],
                        }
                        for column in columns
                    ],
                    "primary_key": primary_key_columns,
                }
            )

            if object_type != "table":
                continue

            if not primary_key_columns:
                findings.append(
                    {
                        "severity": "LOW",
                        "object": name,
                        "issue": "Table has no declared primary key.",
                        "recommendation": "Add a primary key if each row should have a stable unique identifier.",
                    }
                )

            indexes = connection.execute(
                f"PRAGMA index_list({quoted_name})"
            ).fetchall()
            indexed_prefixes = []
            for index in indexes:
                index_columns = connection.execute(
                    f"PRAGMA index_info({_quoted_identifier(index[1])})"
                ).fetchall()
                indexed_prefixes.append(
                    [column[2] for column in index_columns if column[2] is not None]
                )

            foreign_keys = connection.execute(
                f"PRAGMA foreign_key_list({quoted_name})"
            ).fetchall()
            foreign_key_groups: Dict[int, List[Any]] = {}
            for foreign_key in foreign_keys:
                foreign_key_groups.setdefault(foreign_key[0], []).append(foreign_key)

            for foreign_key_columns in foreign_key_groups.values():
                ordered_columns = [
                    entry[3]
                    for entry in sorted(foreign_key_columns, key=lambda item: item[1])
                ]
                if not any(
                    index_columns[:len(ordered_columns)] == ordered_columns
                    for index_columns in indexed_prefixes
                ):
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "object": name,
                            "issue": (
                                "Foreign key columns "
                                f"{', '.join(ordered_columns)} have no supporting index."
                            ),
                            "recommendation": "Consider indexing the foreign-key columns to improve joins and constraint checks.",
                        }
                    )

        return {
            "status": "analyzed",
            "analysis_scope": "schema metadata only; table rows were not read and stored SQL text was not returned or executed",
            "summary": {
                "table_count": sum(item["type"] == "table" for item in tables),
                "view_count": sum(item["type"] == "view" for item in tables),
                "column_count": column_count,
                "finding_count": len(findings),
            },
            "tables": tables,
            "findings": findings,
        }
    except sqlite3.DatabaseError as error:
        raise ValueError("Unable to analyze the SQLite database schema.") from error


def analyze_sqlite_path(database_path: Path) -> Dict[str, Any]:
    try:
        resolved_path = database_path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("Configured SQLite database file was not found.") from error
    if not resolved_path.is_file():
        raise ValueError("Configured SQLite database path is not a file.")
    try:
        database_size = resolved_path.stat().st_size
    except OSError as error:
        raise ValueError("Unable to read the configured SQLite database file.") from error
    if database_size > MAX_DATABASE_BYTES:
        raise ValueError("Database exceeds the 16 MiB analysis limit.")

    uri = f"{resolved_path.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=1)
    except sqlite3.DatabaseError as error:
        raise ValueError("Unable to open the configured SQLite database.") from error
    try:
        return _analyze_connection(connection)
    finally:
        connection.close()


def analyze_sqlite_database(contents: bytes) -> Dict[str, Any]:
    if len(contents) > MAX_DATABASE_BYTES:
        raise ValueError("Database exceeds the 16 MiB analysis limit.")
    if not contents.startswith(SQLITE_HEADER):
        raise ValueError("The uploaded file is not a SQLite database.")

    with tempfile.TemporaryDirectory(prefix="airds-sqlite-audit-") as directory:
        database_path = Path(directory) / "upload.sqlite"
        database_path.write_bytes(contents)
        uri = f"{database_path.as_uri()}?mode=ro&immutable=1"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1)
        except sqlite3.DatabaseError as error:
            raise ValueError("Unable to open the uploaded SQLite database.") from error
        try:
            return _analyze_connection(connection)
        finally:
            connection.close()
