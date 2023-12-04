import boto3
import threading
from datetime import datetime, timedelta, timezone
from queue import Queue

def audit_access_key(user, iam_client, results_queue):
    keys = iam_client.list_access_keys(UserName=user['UserName'])
    for key in keys.get('AccessKeyMetadata', []):
        if key['Status'] == 'Active':
            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
            last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', None)
            if last_used_date:
                days_unused = (datetime.now(timezone.utc) - last_used_date).days
                if days_unused > 90:
                    results_queue.put(f'{user["UserName"]} - {key["AccessKeyId"]} - Active and unused for {days_unused} days')
            else:
                results_queue.put(f'{user["UserName"]} - {key["AccessKeyId"]} - Active and Never Used')

def audit_access_keys():
    iam = boto3.client('iam')
    users = iam.list_users().get('Users', [])
    
    threads = []
    results_queue = Queue()

    for user in users:
        thread = threading.Thread(target=audit_access_key, args=(user, iam, results_queue))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

    while not results_queue.empty():
        print(results_queue.get())

def main():
    audit_access_keys()

if __name__ == '__main__':
    main()
