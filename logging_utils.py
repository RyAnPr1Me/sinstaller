# Logging for Secure Installer
import datetime
import json

def log_event(event_type, details):
    log_entry = {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'event_type': event_type,
        'details': details
    }
    with open('installer_behavior_log.jsonl', 'a', encoding='utf-8') as logf:
        logf.write(json.dumps(log_entry) + '\n')
