from radius import RadiusUser
import random, string
import argparse
import datetime, time
import sys
import threading

nasip_filename = "nasip.txt"
users_filename = "users.txt"
per_of_users_to_end_abruptly = 25            # %of the users to have the abruptly end flag.
time_between_stats = 10


filepath = sys.argv[0]
if filepath.find("/") >=0 or filepath.find("\\")>=0:
    if filepath.find("/") >=0:                   # for non windows systems
        curdir = filepath[:filepath.rfind("/")]
    else:                                        # for windows systems.
        curdir = filepath[:filepath.rfind("\\")]
else:
    curdir = "."


# read the NAS device details from the file.
# Format of the file is one NAS device per line
# the format of each line is <tail-no>,<nas-ip>,<nas-mac>
nas_devices = []
try:
    with open(curdir+"/"+nasip_filename, "rU") as ifile:
        for line in ifile.readlines():
            line = line.strip()
            if line:
                tail_no, nas_ip, nas_mac = [val.strip() for val in line.split(",")][:3]
                nas_device = {"TailNo" : tail_no, "NASIP" : nas_ip, "NASMAC" : nas_mac, "UserCount" : 0}
                nas_devices.append(nas_device)
except Exception, msg:
    print "Wrong format or NAS IP file doesn't exist."
    print "ERROR:", msg
    sys.exit(-1)


# read the users details from the file.
# Format of the file is one User per line.
# the format of each line is <username>,<password>
users = []
try:
    with open(curdir+"/"+users_filename, "rU") as ifile:
        for line in ifile.readlines():
            line = line.strip()
            if line:
                username, password = [val.strip() for val in line.split(",")][:2]
                user = {"Username" : username, "Password" : password}
                users.append(user)
except Exception, msg:
    print "Wrong format or users file doesn't exist."
    print "ERROR:", msg
    sys.exit(-1)

class Statistics(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, name="Statistics")
        self.user_created = 0
        self.user_active = 0
        self.user_terminated = 0
        self.access_request_sent = 0
        self.total_access_request_sent = 0
        self.access_accept_rcvd = 0
        self.total_access_accept_rcvd = 0
        self.access_reject_rcvd = 0
        self.total_access_reject_rcvd = 0
        self.accounting_request_sent = 0
        self.total_accounting_request_sent = 0
        self.accounting_response_rcvd = 0
        self.total_accounting_response_rcvd = 0

    def incr_user_created(self):
        self.user_created += 1
        self.user_active += 1

    def incr_user_terminated(self):
        self.user_terminated += 1
        self.user_active -= 1

    def incr_access_request_sent(self):
        self.access_request_sent += 1
        self.total_access_request_sent += 1

    def incr_access_accept_rcvd(self):
        self.access_accept_rcvd += 1
        self.total_access_accept_rcvd += 1

    def incr_access_reject_rcvd(self):
        self.access_reject_rcvd += 1
        self.total_access_reject_rcvd += 1

    def incr_accounting_request_sent(self):
        self.accounting_request_sent += 1
        self.total_accounting_request_sent += 1

    def incr_accounting_response_rcvd(self):
        self.accounting_response_rcvd += 1
        self.total_accounting_response_rcvd += 1

    def run(self):
        global time_between_stats, s
        with open("loadtest-status.csv","w") as of:
            of.write('Date,Access Reqeust,Access Accept,Access Reject,Acconunting Request,Accounting Response,Concurrent Sessions\n')
        while True:
            time_str = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            try:
                accReqSent, accAccRcvd, accRejRcvd, acctReqSent, acctResRcvd, userActive = self.access_request_sent, self.access_accept_rcvd, self.access_reject_rcvd, self.accounting_request_sent, self.accounting_response_rcvd, self.user_active
                TaccReqSent, TaccAccRcvd, TaccRejRcvd, TacctReqSent, TacctResRcvd, userCreated = self.total_access_request_sent, self.total_access_accept_rcvd, self.total_access_reject_rcvd, self.total_accounting_request_sent, self.total_accounting_response_rcvd, self.user_created
                
                with open("loadtest-status.csv", "a") as of:
                    of.write("%s,%s,%s,%s,%s,%s,%s\n"%(time_str, accReqSent, accAccRcvd, accRejRcvd, acctReqSent, acctResRcvd, userActive))
                    of.write("%s,%s,%s,%s,%s,%s,%s\n\n"%("",TaccReqSent, TaccAccRcvd, TaccRejRcvd, TacctReqSent, TacctResRcvd, userCreated))
                    
                self.access_request_sent -= accReqSent
                self.access_accept_rcvd -= accAccRcvd
                self.access_reject_rcvd -= accRejRcvd
                self.accounting_request_sent -= acctReqSent
                self.accounting_response_rcvd -= acctResRcvd
                #print len(users)
            except Exception, msg:
                print "ERROR:", msg
            time.sleep(time_between_stats)

# This class initializes the users and spans users at a rate given in the command.
class Runner(threading.Thread):
    def __init__(self, server, secret, no_of_users, duration, acctUpdateInterval, rate, userTs):
        threading.Thread.__init__(self, name = "Runner")
        self.server = server
        self.secret = secret
        self.duration = duration
        self.rate = rate
        self.no_of_users = no_of_users
        self.acctUpdateInterval = acctUpdateInterval
        self.userTs = userTs

    def run(self):
        global users, nas_devices
        test_start = datetime.datetime.now()
        # create a thread for statistics collection.
        stats = Statistics()
        stats.setDaemon(True)
        stats.start()
        # The rate is per sec so find the time should be taken for one user.
        # if the rate is 10, then we will take 100ms for each user.
        # So at the end we will sleep for remaining time. 
        time_to_sleep_between_users = 1/float(self.rate)
        userTs = []
        while self.no_of_users > 0:
            try:
                start = datetime.datetime.now()
                if not len(users):
                    time.sleep(time_to_sleep_between_users)
                    continue
                # Randomly choose one User.
                user = random.choice(users)
                users.remove(user)
                # Randomly choose one NAS device.
                nas_device = random.choice(nas_devices)
                #time_spent = int((datetime.datetime.now() - test_start).total_seconds())
                duration_of_user = random.randint(10, self.duration)
                # increment the user count for this NAS device. this is Used in creating ACCT-Session-ID.
                nas_device["UserCount"] += 1
                # check if the end_abruptly flag should be set or not.
                rand = int(random.random() * 100)
                if rand < per_of_users_to_end_abruptly:
                    end_abruptly = True
                else:
                    end_abruptly = False

                # create a user with the follwing attributes, initilize.
                th = RadiusUser(self.server, self.secret, nas_device["NASIP"], nas_device["NASMAC"],
                                         nas_device["TailNo"], nas_device["UserCount"])
                self.no_of_users -= 1
                #print user, self.no_of_users, "Runner"
                th.initiate(user["Username"], user["Password"], duration_of_user, self.acctUpdateInterval, end_abruptly, stats)
                th.setDaemon(True)
                th.start()
                self.userTs.append(th)
            except Exception, msg:
                print "Runner", msg
                pass
            end = datetime.datetime.now()
            # time to sleep is the amount remaining, i.e; (time to be taken for one user - time we consumed)
            time_to_sleep = (time_to_sleep_between_users - (end -start).total_seconds())
            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
        
def main():
    global users
    parser = argparse.ArgumentParser(description="Run a test for Radius server")
    parser.add_argument("-n", type=int, required=True, help="Number of users to run")
    parser.add_argument("-d", type=int, required=True, help="Duration of the test")
    parser.add_argument("-server", type=str, required=True, help="Radius server")
    parser.add_argument("-secret", type=str, required=True, help="Secret for the radius server")
    parser.add_argument("-r", type=int, default=100, help="Rate of the user creation")
    parser.add_argument("-i", type=int, default=0, help="Accounting Update Interval")
    cli = parser.parse_args()
    no_of_users = cli.n
    duration = cli.d
    server = cli.server
    secret = cli.secret
    rate = cli.r
    acctUpdateInterval = cli.i

    userTs = []
    runner = Runner(server, secret, no_of_users, duration, acctUpdateInterval, rate, userTs)
    runner.setDaemon(True)
    runner.start()
    
    while True:
        found_one_alive = False
        for th in userTs:
            if th.isAlive():
                found_one_alive = True
            elif not th.terminated:
                user = {"Username" : th.username, "Password" : th.password}
                users.append(user)
                th.terminated = True
        if runner.isAlive() or found_one_alive:
            time.sleep(1)
        else:
            break
        #print len(userTs), len(users)
    time.sleep(20)
main()
