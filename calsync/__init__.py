#! /usr/bin/python3

import logging
import icalendar.cal
import requests
import click
import traceback
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

def read_calendar(url: str, auth) -> list:
    response = requests.get(url, auth=auth, timeout=30000)
    response.raise_for_status()

    return icalendar.Calendar.from_ical(response.text)

def events_from_calendar(calendar) -> list:
    def is_event(event) -> bool:
        return event.name == 'VEVENT'

    return [e for e in calendar.subcomponents if is_event(e)]

def find_matching_event(event, collection: list):
    matches = [e for e in collection if e.get('UID', None) == event['UID']]

    if len(matches) > 1:
        raise RuntimeError(f'Found more than one match for UID={event["UID"]}')

    return matches[0] if matches else None

def describe_event(event) -> str:
    description = ''
    if 'SUMMARY' in event:
        description += event['SUMMARY'][:50]

    if 'UID' in event:
        description += f'(UID={event["UID"]})'

    return description or '<invalid-event>'

def lookup_existing_event_url(calendar: str, auth, uid: str):
    with requests.Session() as session:
        session.auth = auth

        query = f'''
        <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop>
              <D:getetag/>
            </D:prop>
            <C:filter>
              <C:comp-filter name="VCALENDAR">
                <C:comp-filter name="VEVENT">
                  <C:prop-filter name="UID">
                    <C:text-match>{escape(uid)}</C:text-match>
                  </C:prop-filter>
                </C:comp-filter>
              </C:comp-filter>
            </C:filter>
            </C:calendar-query>'''

        response = session.request(url=calendar, method='REPORT', data=query)
        response.raise_for_status()

    tree = ElementTree.fromstring(response.text)

    entries = tree.findall('./{DAV:}response/{DAV:}href')
    if len(entries) != 1:
        raise NotFoundException(f'Unique event with UID {uid} not found ({len(entries)} matches)')

    # The url might contain the collection name, but all that we want is the file name
    return f'{calendar}/{entries[0].text.split("/")[-1]}'

def save_event(url: str, auth, event, update: bool):
    name = event['UID']

    event_url = None
    if update:
        # Some calendar implementation don't guarantee that event URL's matches their UID
        # So before trying to save the event, look up its actual URL, if the server supports propfind

        try:
            event_url = lookup_existing_event_url(url, auth, name)
            logging.debug(f'UID lookup for "{name}" returned: {event_url}')
        except:
            logging.warning(f'Failed to look up URL for event: {name}, {traceback.format_exc()}')


    # If this is a new event, or no matching URL was found, construct our own based on the UID
    if event_url is None:
        if not name.endswith('.ics'):
            name += '.ics' # Note: this makes the assumption that the caldav server event file matches the UID, which might not be true with all implementations

        event_url = f'{url}{"/" if not url.endswith("/") else ""}{name}'

    calendar = icalendar.Calendar()
    calendar.add_component(event)
    calendar['VERSION'] = '2.0'
    calendar['PRODID'] = 'calsync'

    response = requests.put(event_url, auth=auth, data=calendar.to_ical(), timeout=300)
    response.raise_for_status()


def sync(input_calendar: str, output_calendar: str, input_auth = None, output_auth = None, dry_run: bool = False):
    input_events = events_from_calendar(read_calendar(input_calendar, input_auth))
    output_events = events_from_calendar(read_calendar(output_calendar, output_auth))

    logging.debug(f'Processing events (inputs={len(input_events)}, outputs={len(output_events)})')

    new_events = []
    events_to_update = []
    for e in input_events:
        existing_event = find_matching_event(e, output_events)
        if existing_event is None:
            new_events.append(e)
        elif 'SEQUENCE' not in e:
            logging.warn(f'Event {e["UID"]} has no SEQUENCE information, skipping update')
            continue
        elif e['SEQUENCE'] > existing_event.get('SEQUENCE', 0):
            events_to_update.append(e)

    logging.info(f'{len(new_events)} new events, {len(events_to_update)} events to update')

    for e in new_events:
        logging.info(f'Creating new event for: {describe_event(e)}')

        if dry_run:
            continue

        save_event(output_calendar, output_auth, e, update=False)

    for e in events_to_update:
        logging.info(f'Updating event for: {describe_event(e)}. SEQUENCE={e["SEQUENCE"]}')

        if dry_run:
            continue

        save_event(output_calendar, output_auth, e, update=True)

    return new_events, events_to_update


@click.command()
@click.argument('input_calendar')
@click.argument('output_calendar')
@click.option('--input-username', default=None)
@click.option('--input-password', default=None)
@click.option('--output-username', default=None)
@click.option('--output-password', default=None)
@click.option('--debug', is_flag=True)
@click.option('--dry-run', is_flag=True)
def main(input_calendar: str, output_calendar: str, input_username: str, input_password: str, output_username: str, output_password: str, debug: bool, dry_run: bool):
    try:
        logging.basicConfig(level=logging.DEBUG)

        input_auth=None

        if input_username is not None:
            assert input_password is not None
            input_auth = HTTPBasicAuth(input_username, input_password)

        output_auth = None
        if output_username is not None:
            assert output_password is not None
            output_auth = HTTPBasicAuth(output_username, output_password)

        sync(input_calendar, output_calendar, input_auth, output_auth, dry_run)

    except:
        if not debug:
            raise

        import traceback
        import pdb

        traceback.print_exc()
        pdb.post_mortem()

