# -*- Mode: python; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 40 -*-
# vim: set filetype=python:
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from collections import deque
import argparse
import csv
import re
from uuid import UUID

class XPerfSession:
    def __init__(self):
        self.attrs = set()
        self.evtkey = dict()
        self.evtset = set()

    def match_events(self, row):
        # Make a shallow copy because events will mutate the event set
        local_evtset = self.evtset.copy()
        for e in local_evtset:
            e.do_match(row)

class XPerfAttribute:
    def __init__(self, events, persistent=False):
        for e in events:
            e.set_attr(self)
        self.evtlist = events
        self.seen_evtlist = []
        self.persistent = persistent

    def set_session(self, sess):
        self.sess = sess
        sess.evtset.update(self.evtlist)
        sess.attrs.add(self)

    def get_field_index(self, key, field):
        return self.sess.evtkey[key][field]

    def on_event_matched(self, evt):
        if not evt in self.evtlist:
            raise ValueError(f"Event mismatch: \"{evt!s}\" is not in this attribute's event list")
        if not self.persistent:
            self.evtlist.remove(evt)
            self.seen_evtlist.append(evt)
            self.sess.evtset.remove(evt)
            if len(self.evtlist):
                self.evtlist[0].set_data(evt.get_data())
        if not len(self.evtlist):
            self.process()

    def process(self):
        self.sess.attrs.remove(self)

class XPerfInterval(XPerfAttribute):
    def __init__(self, startevt, endevt):
        XPerfAttribute.__init__(self, [startevt, endevt])

    def process(self):
        super().process()
        end = self.seen_evtlist[-1]
        start = self.seen_evtlist[0]
        duration = end.get_timestamp() - start.get_timestamp()
        print(f"Interval from [{start!s}] to [{end!s}] took [{duration!s}] milliseconds.")

class XPerfCounter(XPerfAttribute):
    def __init__(self, evt):
        XPerfAttribute.__init__(self, [evt], True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            return

        self.process()

class XPerfEvent:
    # These keys are used to reference accumulated data that is passed across
    # events by |self.data|
    EVENT_DATA_PID = 'pid' # The pid recorded by a process or thread related event
    EVENT_DATA_CMD_LINE = 'cmd_line' # The command line recorded by a ProcessStart event
    EVENT_DATA_TID = 'tid' # The tid recorded by a thread related event

    def __init__(self, key):
        self.key = key
        self.timestamp_index = None
        self.data = dict()

    def set_attr(self, attr):
        self.attr = attr

    def set_data(self, data):
        self.data = data

    def get_data(self):
        return self.data

    def get_field_index(self, field):
        return self.attr.get_field_index(self.key, field)

    def do_match(self, row):
        if not self.match(row):
            return False

        if not self.timestamp_index:
            self.timestamp_index = self.get_field_index('TimeStamp')
        # Convert microseconds to milliseconds
        self.timestamp = float(row[self.timestamp_index]) / 1000.0
        self.attr.on_event_matched(self)
        return True

    def match(self, row):
        return self.key == row[0]

    def get_timestamp(self):
        return self.timestamp

class Nth:
    def __init__(self, N, event):
        self.event = event
        self.N = N
        self.match_count = 0
        # We act as the "attr" for self.event
        self.event.set_attr(self)

    def on_event_matched(self, evt):
        if evt != self.event:
            raise ValueError("We are not wrapping this event")
        self.match_count = self.match_count + 1
        if self.match_count == self.N:
            self.attr.on_event_matched(self)

    def set_attr(self, attr):
        self.attr = attr

    def set_data(self, data):
        self.event.set_data(data)

    def get_data(self):
        return self.event.get_data()

    def get_field_index(self, key, field):
        return self.attr.get_field_index(key, field)

    def do_match(self, row):
        self.event.do_match(row)

    def get_timestamp(self):
        return self.event.get_timestamp()

    def __str__(self):
        return f"{self.N!s}th [{self.event!s}]"

class WhenThen:
    def __init__(self, events):
        if len(events) < 2:
            raise ValueError("Why are you using this?")
        self.events = deque(events)
        for e in self.events:
            e.set_attr(self)
        self.seen_events = []

    def on_event_matched(self, evt):
        if evt != self.events[0]:
            raise ValueError("We are not executing this event")
        # Move the event from events queue to seen_events
        self.events.popleft()
        self.seen_events.append(evt)
        if len(self.events):
            # Transfer event data to the next event that will run
            self.events[0].set_data(evt.get_data())
        else:
            self.attr.on_event_matched(self)

    def set_attr(self, attr):
        self.attr = attr

    def set_data(self, data):
        self.events[0].set_data(data)

    def get_data(self):
        return self.seen_events[-1].get_data()

    def get_field_index(self, key, field):
        return self.attr.get_field_index(key, field)

    def do_match(self, row):
        self.events[0].do_match(row)

    def get_timestamp(self):
        return self.seen_events[-1].get_timestamp()

    def __str__(self):
        result = str()
        for e in self.seen_events[:-1]:
            result += f"When [{e!s}], "
        result += f"then [{self.seen_events[-1]!s}]"
        return result

class ClassicEvent(XPerfEvent):
    guid_index = None

    def __init__(self, guidstr):
        XPerfEvent.__init__(self, 'UnknownEvent/Classic')
        self.guid = UUID(guidstr)

    def match(self, row):
        if not super().match(row):
            return False

        if not ClassicEvent.guid_index:
            ClassicEvent.guid_index = self.get_field_index('EventGuid')
        guid = UUID(row[ClassicEvent.guid_index])
        return guid.int == self.guid.int

    def __str__(self):
        return f"User event (classic): [{self.guid!s}]"

class SessionStoreWindowRestored(ClassicEvent):
    def __init__(self):
        ClassicEvent.__init__(self, '{917B96B1-ECAD-4DAB-A760-8D49027748AE}')

    def __str__(self):
        return "Firefox Session Store Window Restored"

def tokenize_cmd_line(cmd_line_str):
    result = []
    quoted = False
    current = str()

    for c in cmd_line_str:
        if quoted:
            if c == '"':
                quoted = False
        else:
            if c == '"':
                quoted = True
            elif c == ' ':
                result.append(current)
                current = str()
                continue

        current += c

    # Capture the final token
    if len(current):
        result.append(current)

    return [ t.strip('"') for t in result ]

class ProcessStart(XPerfEvent):
    cmd_line_index = None
    process_index = None
    pid_extractor = re.compile('[^(]+\((\d+)\)')

    def __init__(self, leafname):
        XPerfEvent.__init__(self, 'P-Start')
        self.leafname = leafname.lower()

    def match(self, row):
        if not super().match(row):
            return False

        if not ProcessStart.cmd_line_index:
            ProcessStart.cmd_line_index = self.get_field_index('Command Line')

        cmd_line = row[ProcessStart.cmd_line_index]
        tokens = tokenize_cmd_line(cmd_line)
        executable = tokens[0].lower()

        if not executable.endswith(self.leafname):
            return False

        if not ProcessStart.process_index:
            ProcessStart.process_index = self.get_field_index('Process Name ( PID)')

        m = ProcessStart.pid_extractor.match(row[ProcessStart.process_index])
        pid = int(m.group(1))
        self.data[XPerfEvent.EVENT_DATA_PID] = pid

        if not XPerfEvent.EVENT_DATA_CMD_LINE in self.data:
            self.data[XPerfEvent.EVENT_DATA_CMD_LINE] = dict()

        self.data[XPerfEvent.EVENT_DATA_CMD_LINE][pid] = tokens
        return True

    def __str__(self):
        return f"Start of a [{self.leafname!s}] process"

class ThreadStart(XPerfEvent):
    process_index = None
    tid_index = None
    pid_extractor = re.compile('[^(]+\((\d+)\)')

    def __init__(self):
        XPerfEvent.__init__(self, 'T-Start')

    def match(self, row):
        if not super().match(row):
            return False

        if not ThreadStart.process_index:
            ThreadStart.process_index = self.get_field_index('Process Name ( PID)')

        m = ThreadStart.pid_extractor.match(row[ThreadStart.process_index])
        if not self.data[XPerfEvent.EVENT_DATA_PID] == int(m.group(1)):
            return False

        if not ThreadStart.tid_index:
            ThreadStart.tid_index = self.get_field_index('ThreadID')

        self.data[XPerfEvent.EVENT_DATA_TID] = int(row[ThreadStart.tid_index])
        return True

    def __str__(self):
        return f"Thread start in process [{self.data[XPerfEvent.EVENT_DATA_PID]}]"

class ReadyThread(XPerfEvent):
    tid_index = None

    def __init__(self):
        XPerfEvent.__init__(self, 'ReadyThread')

    def set_data(self, data):
        super().set_data(data)

    def match(self, row):
        if not super().match(row):
            return False

        if not ReadyThread.tid_index:
            ReadyThread.tid_index = self.get_field_index('Rdy TID')

        if not XPerfEvent.EVENT_DATA_TID in self.data:
            return False

        return self.data[XPerfEvent.EVENT_DATA_TID] == int(row[ReadyThread.tid_index])

    def __str__(self):
        return f"Thread [{self.data[XPerfEvent.EVENT_DATA_TID]!s}] is ready"

class ContextSwitchToThread(XPerfEvent):
    tid_index = None

    def __init__(self):
        XPerfEvent.__init__(self, 'CSwitch')

    def match(self, row):
        if not super().match(row):
            return False

        if not ContextSwitchToThread.tid_index:
            ContextSwitchToThread.tid_index = self.get_field_index('New TID')

        if not XPerfEvent.EVENT_DATA_TID in self.data:
            return False

        return self.data[XPerfEvent.EVENT_DATA_TID] == int(row[ContextSwitchToThread.tid_index])

    def __str__(self):
        return f"Context switch to thread [{self.data[XPerfEvent.EVENT_DATA_TID]!s}]"

class XPerfFile:
    def __init__(self, etlfile=None, csvfile=None):
        self.etlfile = etlfile
        self.csvfile = csvfile
        self.sess = XPerfSession()

    def add_attr(self, attr):
        attr.set_session(self.sess)

    def load(self):
        if self.etlfile:
            self.csvfile = etl2csv(self.etlfile)

        if not self.csvfile:
            return False

        self.data = self.filter_xperf_header(csv.reader(open(self.csvfile, newline=''), delimiter=',', quotechar='"', quoting=csv.QUOTE_NONE, skipinitialspace=True))

        return True

    def filter_xperf_header(self, csvdata):
        state = -1

        for row in csvdata:
            if not len(row):
                continue

            if state < 0:
                if row[0] == "BeginHeader":
                    state = 0
                continue

            if state == 0:
                if row[0] == "EndHeader":
                    state = 1
                    continue

                # Map field names to indices
                self.sess.evtkey[row[0]] = {v: k + 1 for k, v in enumerate(row[1:])}
                continue

            if state >= 1:
                state = state + 1

            if state > 2:
                yield row

    def analyze(self):
        for row in self.data:
            self.sess.match_events(row)
            if len(self.sess.attrs) == 0:
                # No more attrs to look for, we might as well quit
                return

def main():
    parser = argparse.ArgumentParser();
    reqd_group=parser.add_mutually_exclusive_group(required=True)
    reqd_group.add_argument('--etl', help='An input .etl file')
    reqd_group.add_argument('--csvin', help='An input .csv file previously converted from an .etl file')
    parser.add_argument('--csvout', required=False, help='Specify a path to save the interim csv to disk')
    args = parser.parse_args()

    etl=XPerfFile(etlfile=args.etl, csvfile=args.csvin)
    etl.load()

    fxstart1 = ProcessStart('firefox.exe')
    sess_restore = SessionStoreWindowRestored()
    interval1 = XPerfInterval(fxstart1, sess_restore)
    etl.add_attr(interval1)

    fxstart2 = ProcessStart('firefox.exe')
    ready = WhenThen([Nth(2, ProcessStart('firefox.exe')), ThreadStart(), ReadyThread()])
    interval2 = XPerfInterval(fxstart2, ready)
    etl.add_attr(interval2)

    etl.analyze()


if __name__ == "__main__":
    main()
