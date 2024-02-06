import boto3
import threading
from datetime import datetime, timedelta, timezone
from queue import Queue
import csv  # Import the csv module

def audit_console_access(user, iam_client, results_queue):
    if user.get('PasswordLastUsed', None) is not None:
        days_since_last_login = (datetime.now(timezone.utc) - user['PasswordLastUsed']).days
        if days_since_last_login > 90:
            results_queue.put([user["UserName"], 'Console access not used', f'{days_since_last_login} days'])
    elif user.get('PasswordLastUsed') is None and user.get('PasswordEnabled', False):
        results_queue.put([user["UserName"], 'Console access', 'Never Used'])

def audit_access_key(user, iam_client, results_queue):
    keys = iam_client.list_access_keys(UserName=user['UserName'])
    for key in keys.get('AccessKeyMetadata', []):
        if key['Status'] == 'Active':
            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
            last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', None)
            if last_used_date:
                days_unused = (datetime.now(timezone.utc) - last_used_date).days
                if days_unused > 90:
                    results_queue.put([user["UserName"], key["AccessKeyId"], 'Active access key unused', f'{days_unused} days'])
            else:
                results_queue.put([user["UserName"], key["AccessKeyId"], 'Active access key', 'Never Used'])

def audit_user(iam_client, user, results_queue):
    audit_console_access(user, iam_client, results_queue)
    audit_access_key(user, iam_client, results_queue)

def audit_iam_users(aws_access_key_id, aws_secret_access_key, aws_session_token=None):
    iam = boto3.client(
        'iam',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )

    users = iam.list_users().get('Users', [])
    threads = []
    results_queue = Queue()

    for user in users:
        thread = threading.Thread(target=audit_user, args=(iam, user, results_queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    # Write results to a CSV file
    with open('iam_audit_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['UserName', 'Issue', 'Details'])  # Writing the header
        while not results_queue.empty():
            writer.writerow(results_queue.get())

def main():
    aws_access_key_id = '<ACCESS_KEY>'
    aws_secret_access_key = '<SECRET_KEY>'
    # aws_session_token = 'YOUR_SESSION_TOKEN'  # Uncomment if you have a session token

    audit_iam_users(aws_access_key_id, aws_secret_access_key)  # Add aws_session_token if needed

if __name__ == '__main__':
    main()

