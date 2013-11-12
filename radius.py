import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import random, datetime
import logging, os, time
import socket, threading

# Find the directory of the file. Since this file can be called from anywhere,
# we need to set to the directory where this file resides.  
try:
     if __file__.find("/") >=0:                   # for non windows systems
          curdir = __file__[:__file__.rfind("/")]
     else:                                        # for windows systems.
          curdir = __file__[:__file__.rfind("\\")]
     os.chdir(curdir)
     os.mkdir("logs")                             # create directory for logs.
except:
    pass

#path to dictionary
accDictionaryPath = "dict/dictionary"
# lists to store used user IP, MAC addresses so that it will not allocated again.
usedIP = []
usedMAC = []
dict = Dictionary(accDictionaryPath)


def randomMAC():
    while True:
        mac_digits = [ 0x00, 0x16, 0x3e, random.randint(0x00, 0x7f),
                       random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
        mac = ':'.join(map(lambda x: "%02X" % x, mac_digits))
        if not mac in usedMAC:
            usedMAC.append(mac)
            return mac

def randomIP(nasIP):
    while True:
        a,b,c,d = map(int, nasIP.split("."))[:4]
        ip = ".".join(map(str, [a, b, c, random.randint(3,200)]))
        if not ip in usedIP:
            usedIP.append(ip)
            return ip

class UserError(Exception):
    """This is used represnt any Exception occured during user authentication,
    accounting requests.
    """
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)    

class RadiusUser(threading.Thread):
    """
    This class is used to create a radius client connection and
    send authentication, accouting requests. This class imports
    Thread class.
    """
    def __init__(self, server, secret, nasIP, nasMAC, goGoTailNumber, userID):
        threading.Thread.__init__(self, name = (nasMAC+"-"+str(userID)))
        # stroe the parameters used
        self.server = server
        self.secret = secret
        self.nasIP = nasIP
        self.nasMacAddr = nasMAC
        self.goGoTailNumber = goGoTailNumber
        self.userID = userID
        self.initiated = False
        
    def initiate(self, username, password, duration, acctUpdateInterval, abruptlyEnd, stats):
        global dict
	self.username = username
        self.password = password
        self.duration = duration
        self.abruptlyEnd = abruptlyEnd
        self.acctUpdateInterval = acctUpdateInterval
        self.stats = stats

        # create a framed IP and MAC adress for user.
        self.framedIP = randomIP(self.nasIP)
        self.userMacAddr = randomMAC()
        
        # create a logger for this user.
        self.logger = logging.getLogger(self.username)
        
        # create a formatter for writing into logging file. The format is "<time>: <level>: <string>"
        self.formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')

        # create a file handler for writing the log info to the file.
        date_str = datetime.datetime.now().strftime("%Y%m%d%H%M")
        self.handle = logging.FileHandler("logs/"+username+"-"+date_str+".log")
        self.handle.setFormatter(self.formatter)
        self.logger.addHandler(self.handle)
        self.logger.setLevel(logging.DEBUG)

        # write the information into log file. 
        self.logger.debug("Starting the client for the user %s to the server %s\n", self.username, self.server)
        self.logger.debug("DURATION of the TEST: %d", self.duration)
        self.logger.debug("NAS-IP: %s", self.nasIP)
        self.logger.debug("NAS-MAC-ADDR: %s", self.nasMacAddr) 
        self.logger.debug("Abruptly End: %s", self.abruptlyEnd)
        self.logger.debug("Framed-IP: %s", self.framedIP)
        self.logger.debug("User-MAC-Addr: %s", self.userMacAddr)
        
        # create a connection to the server
        self.srv = Client(server=self.server, secret=self.secret,
                          dict=dict)
        self.initiated = True
        self.terminated = False

    # Function to start the user activity.
    def run(self):
        try:
            self.stats.incr_user_created()
            try:
                self.logger.debug("\n")
                # send Authentication Request with Service Type 8 
                if not self.authRequest(service_type=8):
                    # The request is not Accept so log the event and exit.
                    print "Auth Failed Service Type: 8 for user", self.username
                    self.logger.error("AUTH Failed for Service type 8, Ending the test for this user")
                    raise Exception
                # send Authentication Request with Service Type 1
                if not self.authRequest(service_type=1):
                    # The request is not Accept so log the event and exit.
                    print "Auth Failed, Service Type: 1 for user", self.username
                    self.logger.error("AUTH Failed for Service Type 1, Ending the test for this user")
                    raise Exception
            except Exception as e:
                # there is some network error. So log it and return.
                print e, self.username
                self.logger.error("Network error, Reason: %s", str(e))
                self.logger.error("Ending the test for this user")
                raise Exception
            
            try:
                self.logger.debug("\n")
                # Send Accounting Start Request.
                self.acctStartRequest()
            except Exception as e:
                # If there is any error like Network Error log the Error and exit.
                print e, self.username
                self.logger.error("Network error, Reason: %s", str(e))
                self.logger.error("Ending the test for this user")
                raise Exception

            # While the Duration is greater than 20 seconds sleep send some Interim Accountings
            while self.duration > 5:
                start = datetime.datetime.now()
                # Choose a random b/w 20 sec and 5 min and sleep for that time.
                if self.acctUpdateInterval:
                    time_to_sleep = self.acctUpdateInterval
                else:
                    time_to_sleep = random.randint(20,300)
                if time_to_sleep > self.duration:
                    time_to_sleep = self.duration
                time.sleep(time_to_sleep)
                try:
                    self.logger.debug("\n")
                    # Send Accounting Interim
                    self.acctUpdateRequest()
                except Exception as e:
                    # If there is any error like Network Error log the Error.
                    # Here we don't end the session as this is just a update.
                    print e, self.username
                    self.logger.error("Network error, Reason: %s", str(e))

                # If the user has Abruptly end flag set then end the test for this user if we choose True.
                if random.choice([True,False]) and self.abruptlyEnd:
                    self.logger.debug("User has abruptly end flag so ending the test with out AcctStop")
                    raise Exception
                # Subtract the time we spent from the duration of user.
                end = datetime.datetime.now()
                self.duration -= int((end-start).total_seconds())

            # Sleep for a random sec b/w 10 and 60 to send Accounting stop.
            time.sleep(random.randint(10,30))
            # If the Abruptly end flag set then end the test for this user
            if self.abruptlyEnd:
                self.logger.debug("User has abruptly end flag so ending the test with out AcctStop")
                raise Exception
            
            try:
                self.logger.debug("\n")
                # Send Accounting Stop
                self.acctStopRequest()
            except Exception as e:
                # If there is any error like Network Error log the Error and exit.
                print e, self.username
                self.logger.error("Network error, Reason: %s", str(e))
                self.logger.error("Ending the test for this user")
                raise Exception
        except:
            pass
        #Ending the test for this user.
        self.logger.debug("Ending the test for this user")
        self.stats.incr_user_terminated()
        self.handle.close()
        del self.logger, self.formatter
        

    # Function to send Authentication Request to the User.
    def authRequest(self, service_type):
        # This is just for error checking in case if some one calls
        # this function with out calling initiate function.
        if not self.initiated:
            raise UserError('User is not at initialized')

        # create a Accounting Session id.
        self.acctSessionID = "%s-%d-%s-%d"%(self.goGoTailNumber, time.time()*1000, self.userMacAddr.replace(":",""), self.userID)
        
        # create a Auth Request Packet.
        req = self.srv.CreateAuthPacket(code=pyrad.packet.AccessRequest)

        # populate the attributes in authentication Request.
        req['User-Name'] = self.username
        if self.password and len(self.password):
            req['User-Password'] = req.PwCrypt(self.password)
        req['GoGo-Airline'] = 'BA01'
        req['Service-Type'] = service_type
        req['Proxy-State'] = '3237,3134'
        req['Called-Station-Id'] = self.userMacAddr
        req['NAS-Identifier'] = "C08386"
        req['NAS-Port-Type'] = 19
        req['Framed-IP-Address'] = self.framedIP
        req['Calling-Station-Id'] = self.nasMacAddr
        req['NAS-IP-Address'] = self.nasIP
        req['WISPr-Location-ID'] = "airline=BA01,tail=01009,network="
        req['WISPr-Location-Name'] = "TEST LLC,BA01_01009"
        req['Acct-Session-Id'] = self.acctSessionID
        req['GoGo-Tail-Number'] = self.goGoTailNumber
        req['GoGo-Private-IP-Address'] = "192.168.1.179"

        # Logging the Authentication Request.
        self.logger.debug("Creating Authentication Request with the following Attributes:")
        for key in req.keys():
            try:
                self.logger.debug("%s: %s", key, req[key])
            except Exception, msg:
                pass

        # send the Packet to the server
        self.stats.incr_access_request_sent()
        try:
            resp = self.srv.SendPacket(req)
        except pyrad.client.Timeout:
            raise UserError("Radius server timed out")
        except socket.error,error:
            raise UserError("Network error: "+error[1])

        # Logging the Authentication Response.
        self.logger.debug("\n")
        if resp.code == pyrad.packet.AccessAccept:
            self.logger.debug("Received response with code: %d, Accepted", resp.code)
            self.stats.incr_access_accept_rcvd()
        else:
            self.logger.debug("Received response with code: %d, Rejected", resp.code)
            self.stats.incr_access_reject_rcvd()
        for key in resp.keys():
            try:
                self.logger.debug("%s: %s", key, resp[key])
            except:
                pass
        
        # Return False if the Response code is not Access Accept.
        return (resp.code == pyrad.packet.AccessAccept)
    # end of Access request function


    # Function to send Accounting Start Request to the user.
    def acctStartRequest(self):
        # This is just for error checking in case if some one calls
        # this function with out calling initiate function.
        if not self.initiated:
            raise UserError('User is not at initialized')

        # Create a Accouting Packet.
        req = self.srv.CreateAcctPacket()

        # Populate the Packet with Accounting Attributes
        req["Acct-Status-Type"] = 1
        req['User-Name'] = self.username
        req["GoGo-Airline"] = "BA01"
        req["Proxy-State"] = "3239,3131"
        req['Called-Station-Id'] = self.userMacAddr
        req['NAS-Identifier'] = "C08386"
        req['Framed-IP-Address'] = self.framedIP
        req['NAS-Port-Type'] = 19
        req['Calling-Station-Id'] = self.nasMacAddr
        req['NAS-IP-Address'] = self.nasIP
        req['WISPr-Location-ID'] = "airline=BA01,tail=01009,network="
        req['WISPr-Location-Name'] = "TEST LLC,BA01_01009"
        req['GoGo-Tail-Number'] = self.goGoTailNumber
        req['Acct-Session-Id'] = self.acctSessionID
        req['GoGo-Private-IP-Address'] = "192.168.1.179"

        # Logging the Accounting Start Request.
        self.logger.debug("Creating Accounting start Request with the following Attributes:")
        for key in req.keys():
            try:
                self.logger.debug("%s: %s", key, req[key])
            except Exception, msg:
                pass

        # Send the Request to the server.
        self.stats.incr_accounting_request_sent()
        try:
            resp = self.srv.SendPacket(req)
        except pyrad.client.Timeout:
            raise UserError("Radius server timed out")
        except socket.error,error:
            raise UserError("Network error: "+error[1])

        self.stats.incr_accounting_response_rcvd()
        # Logging the Accounting Response.
        self.logger.debug("\n")
        self.logger.debug("Received response with following attributes:")
        for key in resp.keys():
            try:
                self.logger.debug("%s: %s", key, resp[key])
            except:
                pass
        self.start_time = datetime.datetime.now()
    # End of Accounting Start function

    def acctUpdateRequest(self):
        # This is just for error checking in case if some one calls
        # this function with out calling initiate function.
        if not self.initiated:
            raise UserError('User is not at initialized')

        # Find the Session time and reset the start time to current time.
        session_time = int((datetime.datetime.now() - self.start_time).total_seconds())
        self.start_time = datetime.datetime.now()
        
        # Create a Accounting Packet.
        req = self.srv.CreateAcctPacket()

        # Populate the Interim Accounting attributes.
        req["Acct-Status-Type"] = 3
        req['User-Name'] = self.username
        req["Proxy-State"] = "3330,3132"
        req['Framed-IP-Address'] = self.framedIP
        req['Calling-Station-Id'] = self.nasMacAddr
        req['NAS-IP-Address'] = self.nasIP
        req['GoGo-Tail-Number'] = self.goGoTailNumber
        req['Acct-Session-Id'] = self.acctSessionID
        req["GoGo-Airline"] = "BA01"
        req['Called-Station-Id'] = self.userMacAddr
        req['NAS-Identifier'] = "C08386"
        req['NAS-Port-Type'] = 19
        req['WISPr-Location-ID'] = "airline=BA01,tail=01009,network="
        req['WISPr-Location-Name'] = "TEST LLC,BA01_01009"
        req["Acct-Session-Time"] = session_time
        req['GoGo-Private-IP-Address'] = "192.168.1.179"

        req["GoGo-Total-Output-Gigawords"] = 0
        req["GoGo-Total-Input-Gigawords"] = 0
        req["GoGo-Total-Output-Voice-Packets"] = 0
        req["GoGo-Total-Input-Voice-Packets"] = 0
        req["GoGo-Total-Output-Voice-Gigawords"] = 0
        req["GoGo-Total-Input-Voice-Gigawords"] = 0
        req["GoGo-Total-Output-Voice-Octets"] = 0
        req["GoGo-Total-Input-Voice-Octets"] = 0

        req["GoGo-Acct-Output-Voice-Packets"] = 0
        req["GoGo-Acct-Input-Voice-Packets"] = 0
        req["GoGo-Acct-Output-Voice-Gigawords"] = 0
        req["GoGo-Acct-Input-Voice-Gigawords"] = 0
        req["GoGo-Acct-Output-Voice-Octets"] = 0
        req["GoGo-Acct-Input-Voice-Octets"] = 0

        req["Acct-Output-Gigawords"] = 0
        req["Acct-Input-Gigawords"] = 0

        input_bytes = random.randint(1000000, 10000000)
        output_bytes = random.randint(1000000, 10000000)
        input_packets = random.randint(input_bytes/1000, input_bytes/100)
        output_packets = random.randint(output_bytes/1000, output_bytes/100)
        req["GoGo-Total-Output-Packets"] = output_packets
        req["GoGo-Total-Input-Packets"] = input_packets
        req["GoGo-Total-Output-Octets"] = output_bytes
        req["GoGo-Total-Input-Octets"] = input_bytes
        req["Acct-Output-Packets"] = output_packets
        req["Acct-Input-Packets"] = input_packets
        req["Acct-Output-Octets"] = output_bytes
        req["Acct-Input-Octets"] = input_bytes

        # Logging the Accounting Interim.
        self.logger.debug("Creating Accounting Update Request with the following Attributes:")
        for key in req.keys():
            try:
                self.logger.debug("%s: %s", key, req[key])
            except Exception, msg:
                pass

        # Send the Request to the Server.
        self.stats.incr_accounting_request_sent()
        try:
            resp = self.srv.SendPacket(req)
        except pyrad.client.Timeout:
            raise UserError("Radius server timed out")
        except socket.error,error:
            raise UserError("Network error: "+error[1])

        self.stats.incr_accounting_response_rcvd()
        # Logging the Accounting Response.
        self.logger.debug("\n")
        self.logger.debug("Received response with following attributes:")
        for key in resp.keys():
            try:
                self.logger.debug("%s: %s", key, resp[key])
            except:
                pass
    # End of Interim Accounting Update Function.

    def acctStopRequest(self):
        # This is just for error checking in case if some one calls
        # this function with out calling initiate function.
        if not self.initiated:
            raise UserError('User is not at initialized')

        # Find the Session time and reset the start time to current time.
        session_time = int((datetime.datetime.now() - self.start_time).total_seconds())
        self.start_time = datetime.datetime.now()

        # Create a Accounting Packet.
        req = self.srv.CreateAcctPacket()

        # Populate the Accounting Stop attributes.
        req["Acct-Status-Type"] = 2
        req['User-Name'] = self.username
        req["Proxy-State"] = "3330,3132"
        req['Framed-IP-Address'] = self.framedIP
        req['Calling-Station-Id'] = self.nasMacAddr
        req['NAS-IP-Address'] = self.nasIP
        req['GoGo-Tail-Number'] = "01009"
        req['Acct-Session-Id'] = self.acctSessionID
        req["GoGo-Airline"] = "BA01"
        req['Called-Station-Id'] = self.userMacAddr
        req['NAS-Identifier'] = "C08386"
        req['NAS-Port-Type'] = 19
        req['WISPr-Location-ID'] = "airline=BA01,tail=01009,network="
        req['WISPr-Location-Name'] = "TEST LLC,BA01_01009"
        req["Acct-Session-Time"] = session_time
        req['GoGo-Private-IP-Address'] = "192.168.1.179"
        req["Acct-Terminate-Cause"] = 1
        

        req["GoGo-Total-Output-Gigawords"] = 0
        req["GoGo-Total-Input-Gigawords"] = 0
        req["GoGo-Total-Output-Voice-Packets"] = 0
        req["GoGo-Total-Input-Voice-Packets"] = 0
        req["GoGo-Total-Output-Voice-Gigawords"] = 0
        req["GoGo-Total-Input-Voice-Gigawords"] = 0
        req["GoGo-Total-Output-Voice-Octets"] = 0
        req["GoGo-Total-Input-Voice-Octets"] = 0

        req["GoGo-Acct-Output-Voice-Packets"] = 0
        req["GoGo-Acct-Input-Voice-Packets"] = 0
        req["GoGo-Acct-Output-Voice-Gigawords"] = 0
        req["GoGo-Acct-Input-Voice-Gigawords"] = 0
        req["GoGo-Acct-Output-Voice-Octets"] = 0
        req["GoGo-Acct-Input-Voice-Octets"] = 0

        req["Acct-Output-Gigawords"] = 0
        req["Acct-Input-Gigawords"] = 0

        input_bytes = random.randint(1000000, 10000000)
        output_bytes = random.randint(1000000, 10000000)
        input_packets = random.randint(input_bytes/1000, input_bytes/100)
        output_packets = random.randint(output_bytes/1000, output_bytes/100)
        req["GoGo-Total-Output-Packets"] = output_packets
        req["GoGo-Total-Input-Packets"] = input_packets
        req["GoGo-Total-Output-Octets"] = output_bytes
        req["GoGo-Total-Input-Octets"] = input_bytes
        req["Acct-Output-Packets"] = output_packets
        req["Acct-Input-Packets"] = input_packets
        req["Acct-Output-Octets"] = output_bytes
        req["Acct-Input-Octets"] = input_bytes

        # Logging the Accounting Stop.
        self.logger.debug("Creating Accounting Stop Request with the following Attributes:")
        for key in req.keys():
            try:
                self.logger.debug("%s: %s", key, req[key])
            except Exception, msg:
                pass

        # Sending the Request to the server.
        self.stats.incr_accounting_request_sent()
        try:
            resp = self.srv.SendPacket(req)
        except pyrad.client.Timeout:
            raise UserError("Radius server timed out")
        except socket.error,error:
            raise UserError("Network error: "+error[1])

        self.stats.incr_accounting_response_rcvd()
        # Logging the Accounting Response.
        self.logger.debug("\n")
        self.logger.debug("Received response with following attributes:")
        for key in resp.keys():
            try:
                self.logger.debug("%s: %s", key, resp[key])
            except:
                pass
    # End of Accounting Stop Function.
