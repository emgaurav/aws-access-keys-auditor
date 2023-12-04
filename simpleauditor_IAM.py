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

def audit_access_keys(aws_access_key_id, aws_secret_access_key, aws_session_token=None):
    iam = boto3.client(
        'iam', 
        aws_access_key_id=aws_access_key_id, 
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token  # Optional, use if you have a session token
    )
    
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
    # Replace with your actual AWS IAM credentials
    aws_access_key_id = 'YOUR_ACCESS_KEY_ID'
    aws_secret_access_key = 'YOUR_SECRET_ACCESS_KEY'
    # aws_session_token = 'YOUR_SESSION_TOKEN'  # Uncomment if you have a session token

    audit_access_keys(aws_access_key_id, aws_secret_access_key)  # Add aws_session_token if needed

if __name__ == '__main__':
    main()
