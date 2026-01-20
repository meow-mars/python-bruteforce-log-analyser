from datetime import datetime, timedelta

users = {}
users_timestamp = {}
alert_threshold = 3
time_window = timedelta(minutes=5)

alert_export = open('alert.log','a')

with open("sample.log", "r") as file:
    for line in file:
        parts = line.split()
        user = parts[2].split("=")[1]
        ip = parts[3].split("=")[1]
        status = parts[4].split("=")[1]

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
                print("Last login attempt:",users_timestamp[user][ip][-1])

                alert = (f'{users_timestamp[user][ip][-1]} | ALERT | '
                         f'USER: {user} | IP address: {ip} | '
                         f'Attempts: {len(users_timestamp[user][ip])} | '
                         f'Window: 5 minutes\n')

                alert_export.write(alert)

alert_export.close()
