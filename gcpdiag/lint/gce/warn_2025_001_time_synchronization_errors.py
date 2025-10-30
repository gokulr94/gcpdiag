# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Lint as: python3
"""Serial logs don't contain time synchronization errors

Time synchronization issues can cause various problems including Kerberos
authentication failures, TLS/SSL certificate validation errors, database
replication issues, and logging inconsistencies. This rule checks serial logs
for common time synchronization error patterns from NTP, Chrony, and general
system time issues.
"""

from typing import Optional

from gcpdiag import lint, models
from gcpdiag.lint.gce import utils
from gcpdiag.queries import gce
from gcpdiag.queries.logs import LogEntryShort

TIME_SYNC_ERROR_MESSAGES = [
    # NTP related error messages
    'time may be out of sync',
    'System clock is unsynchronized',
    'Time drift detected',
    'no servers can be used, system clock unsynchronized',
    'time reset',
    # Chrony related error messages
    'System clock unsynchronized',
    'Time offset too large',
    r'Can\'t synchronise: no selectable sources',
    # General time errors
    'Clock skew detected',
    'Clock skew too great',
    'Could not receive latest log timestamp from server',
]

logs_by_project = {}


def prepare_rule(context: models.Context):
  filter_str = '''textPayload:(
    "time may be out of sync" OR
    "System clock is unsynchronized" OR
    "Time drift detected" OR
    "no servers can be used" OR
    "time reset" OR
    "Time offset too large" OR
    "Can't synchronise" OR
    "Clock skew detected" OR
    "Clock skew too great" OR
    "Could not receive latest log timestamp"
  )'''
  logs_by_project[context.project_id] = utils.SerialOutputSearch(
      context, search_strings=TIME_SYNC_ERROR_MESSAGES, custom_filter=filter_str)


def run_rule(context: models.Context, report: lint.LintReportRuleInterface):
  # Skip entire rule if serial outputs are unavailable
  if not utils.is_serial_port_one_logs_available(context):
    report.add_skipped(None, 'serial port output is unavailable')
    return

  search = logs_by_project[context.project_id]
  instances = gce.get_instances(context).values()

  if not instances:
    report.add_skipped(None, 'No instances found')
    return

  for instance in sorted(instances, key=lambda i: i.name):
    match: Optional[LogEntryShort] = search.get_last_match(
        instance_id=instance.id)
    if match:
      report.add_failed(
          instance,
          (f'Time synchronization errors detected on instance {instance.name}.\n'
           f'{match.timestamp_iso}: "{match.text}"\n'
           'Verify that the instance can reach metadata.google.internal '
           'and that NTP/Chrony services are properly configured.'))
    else:
      report.add_ok(instance)
