# DIFR - Tools - Plaso

### Overview

[`Plaso`](https://github.com/log2timeline/plaso) is a Python-based engine used
to generate ("super") timelines, based on a number of forensic artefacts.

### Usage

###### Plaso database generation

The first step to generate a timeline through `plaso` is to create a `plaso`
database using `log2timeline.py`.

```bash
# Generates a plaso database, parsing all artefacts available.
log2timeline.py --storage-file <OUTPUT_PLASO_DB> <EVIDENCE_FILE | EVIDENCE_FOLDER>

# Generates a plaso database through Docker, parsing all artefacts available.
docker run -v <HOST_SHARED_FOLDER>:<CONTAINER_SHARED_FOLDER> log2timeline/plaso log2timeline --storage-file <CONTAINER_SHARED_FOLDER>/<OUTPUT_PLASO_DB> <CONTAINER_SHARED_FOLDER>/<EVIDENCE_FILE | EVIDENCE_FOLDER>

# lists the available parsers.
log2timeline.py --parsers list

# Generates a plaso database, using all parsers except the filestat parser (useful for triaged data parsing).
log2timeline.py --parsers '!filestat' --storage-file <OUTPUT_PLASO_DB> <EVIDENCE_FILE | EVIDENCE_FOLDER>
```

The number of events parsed and errors that occurred during parsing can be
reviewed with the `pinfo` script:

```bash
pinfo.py <OUTPUT_PLASO_DB>
```

###### Timeline generation

Once a `plaso` database has been generated with `log2timeline`, the `psort`
script can be used to transform the database in a human-readable timeline.
Multiple output formats are supported, including `json`, `csv`, `TLN`, `xlsx`,
`opensearch` database for ingestion with `Timesketch`, etc.

`psort` uses UTC as its default time zone when outputting events.

```bash
# Lists the supported output format.
psort.py -o list

# Generates a timeline in the specified format based on the provided Plaso database.
psort.py -o <json_line | FORMAT> -w <TIMELINE_OUTPUT> <PLASO_DB>
```
