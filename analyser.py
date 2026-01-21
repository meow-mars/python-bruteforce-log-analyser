from datetime import datetime, timedelta
from ip_utils import classify_ip, get_severity
import argparse
import os

parser = argparse.ArgumentParser(prog="Python Brute-Force Log Analyser",
                                 description="Analyse authentication log files to detect suspicious login behaviour such as repeated failed attempts within a time window.",
                                 epilog="Made by Duy Duc Duong @ Monash University")
parser.add_argument('filename', type=str, help="Logfile name where the analyser will scan and analyse") 
parser.add_argument('-t','--threshold', type=int, default=3, help="Number of failed attempts before flagged")
parser.add_argument('-w','--timewindow', type=int, default=5, help="How far apart the failed login attempts (in minutes) are within which failed attempts count toward the threshold")

args = parser.parse_args()

users = {}
users_timestamp = {}
alert_threshold = args.threshold
time_window = timedelta(minutes=args.timewindow)

alert_export = open('alert.log','a')

if not os.path.exists(args.filename):
    print("Filename does not exist")
    exit(1)

with open(args.filename, "r") as file:
    for line in file:
        parts = line.split()
        user = parts[2].split("=")[1]
        ip = parts[3].split("=")[1]
        status = parts[4].split("=")[1]
        ip_type = classify_ip(ip)
        severity = get_severity(ip_type)

        # Time extraction
        timestamp_str = parts[0] + " " + parts[1]
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

        # Users
        if user not in users:
            users[user] = {}
        
        if user not in users_timestamp:
            users_timestamp[user] = {}

        # Isolation counter
        if status == "FAIL":
      
            if ip not in users[user]:
                users[user][ip] = 0
            
            users[user][ip] += 1
            
        
        # Time window detection
        if status == "FAIL":

            if ip not in users_timestamp[user]:
                users_timestamp[user][ip] = []
            

            # Append
            users_timestamp[user][ip].append(timestamp)

            # Prune check
            timestamp_list = users_timestamp[user][ip]
            timestamp_list = [x for x in timestamp_list if (not (timestamp_list[-1] - x) > time_window)]
            users_timestamp[user][ip] = timestamp_list

            # 3-times check
            if len(users_timestamp[user][ip]) == alert_threshold:
                print("SUSPICIOUS LOGIN ALERT\n----------------------")
                print("User:",user)
                print("IP address:",ip)
                print("IP type:",ip_type)
                print("Severity:",severity)
                print("Last login attempt:",users_timestamp[user][ip][-1],"\n")

                alert = (f'{users_timestamp[user][ip][-1]} | ALERT | '
                         f'USER: {user} | IP address: {ip} | '
                         f'Attempts: {len(users_timestamp[user][ip])} | '
                         f'Window: {time_window} minutes | '
                         f'IP Type: {ip_type} | '
                         f'Severity: {severity}\n')

                alert_export.write(alert)

alert_export.close()
