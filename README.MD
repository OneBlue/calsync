# Calsync

A simple python3 module to synchronize events between calendars

## Installation

Install via:

```
pip3 install git+https://github.com/OneBlue/calsync
```

## Usage

calsync can be used either as a command line tool, or via a python invocation.

### Command line usage

`calsync <input-calendar-url> <output-calendar-url> [--input-username <user>] [--input-password <password>] [--output-username <username>] [--output-password <password>] [--dry-run] [--manual-sequence]`

Arguments:

- `input-calendar-url`: The URL of the calendar to import events from. This calendar is only read from, and not written to
- `output-calendar-url`: The URL of the calendar to write or updates events in.
- `input-username`: The username to authenticate to the input calendar with
- `input-password`: The password to authenticate to the input calendar with
- `output-password`: The password to authenticate to the output calendar with
- `output-password`: The password to authenticate to the outout calendar with
- `--dry-run`: Display the changes between calendars, but don't write any changes
- `--manual-sequence`: Don't use `SEQUENCE` fields to determine wether an event should be updated (manually compare fields instead). This is useful when the input calendar doesn't support SEQUENCE fields.


### Python usage

```python
import calsync
from requests.auth import HTTPBasicAuth

new_events, updated_events = calsync.sync(
  input_calendar=<input_calendar_url>,
  output_calendar=<output_calendar_url>,
  input_auth=HTTPBasicAuth(<username>, <password>), # Optional
  output_auth=HTTPBasicAuth(<username>, <password>)) # Optional
```

### Usage to import facebook events into a CalDAV collection

* Navigate to [this page](https://www.facebook.com/events/calendar)
* Right click -> Copy URL on the 'Add to calendar' button, at the top right corner of the page
* Use this url as the input URL with calsync (no authentication needed)

Sample command line: ` calsync <url-copied-from-facebook> <caldav-calendar-url> --output-username <caldav-username> --output-password <caldav-password>`

### Usage to import partiful calendar events into a CalDAV collection

* Get the calendar collection following [these instructions](https://help.partiful.com/hc/en-us/sections/26025196887707--Calendar-Sync)
* Use this url as the input URL with calsync (no authentication needed)


Sample command line: ` calsync <url-copied-from-partiful> <caldav-calendar-url> --output-username <caldav-username> --output-password <caldav-password> --manual-sequence`

Note: `--manual-sequence` is required because partiful doesn't use `SEQUENCE` fields to track event updates.
