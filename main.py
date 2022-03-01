#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import socket
import socketserver
import re
import sys
import time
import logging
import threading


HOST, PORT = '0.0.0.0', 5060
rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile("^192\.168")
rx_invalid2 = re.compile("^10\.")
# rx_cseq = re.compile("^CSeq:")
# rx_callid = re.compile("Call-ID: (.*)$")
# rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def debugRegister():
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar.keys():
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            try:
                line = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        data = []
        for line in self.data:
            try:
                line = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data

    @staticmethod
    def checkValidity(uri):
        addrport, socketValid, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    @staticmethod
    def getSocketInfo(uri):
        addrport, socketInfo, client_addr, validity = registrar[uri]
        return socketInfo, client_addr

    def getDestination(self):
        destination = ""
        for line in self.data:
            try:
                line = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            try:
                line = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            try:
                line = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line, ";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = "l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        index = 0
        for line in data:
            try:
                data[index] = line.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            index += 1
        text = '\r\n'.join(data)
        self.socket.sendto(bytes(text, "utf-8"), self.client_address)
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        for line in self.data:
            line = line.decode("utf-8")
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar.keys():
                del registrar[fromm]
                self.sendResponse("200 Everything is fine")
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("From: %s - Contact: %s" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debugRegister()
        self.sendResponse("200 Everything is fine")

    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar.keys():
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar.keys() and self.checkValidity(destination):
                socketInvite, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                # noinspection PyAttributeOutsideInit
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socketInvite.sendto(bytes(text, "utf-8"), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar.keys():
                socketAck, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                # noinspection PyAttributeOutsideInit
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socketAck.sendto(bytes(text, "utf-8"), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar.keys():
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar.keys() and self.checkValidity(destination):
                socketNonInvite, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                # noinspection PyAttributeOutsideInit
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socketNonInvite.sendto(bytes(text, "utf-8"), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar.keys():
                socketCode, claddr = self.getSocketInfo(origin)
                # noinspection PyAttributeOutsideInit
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = '\r\n'.join(data)
                socketCode.sendto(bytes(text, "utf-8"), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRequest(self):
        # print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0].decode("utf-8")
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
                self.writeBeginningOfCall(datetime.datetime.now().time())
            elif rx_ack.search(request_uri):
                self.processAck()
                self.writeAnsweringOfCall(datetime.datetime.now().time())
            elif rx_bye.search(request_uri):
                self.processNonInvite()
                self.writeEndOfCall(datetime.datetime.now().time())
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 Everything is fine")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 Everything is fine")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 Everything is fine")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                # print "message %s unknown" % self.data

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0]
        # noinspection PyAttributeOutsideInit
        self.data = data.split(b'\r\n')
        # noinspection PyAttributeOutsideInit
        self.socket = self.request[1]
        request_uri = self.data[0].decode("utf-8")
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")

    def writeBeginningOfCall(self, timeOfCalling):
        phoneCallDiary = open("phoneCallDiary.txt", "a")
        phoneCallDiary.write("Call record:\n\tFrom: " + self.getOrigin() + "\n\tTo: " +
                             self.getDestination() + "\n\tTime of calling: " + str(timeOfCalling.strftime("%H:%M:%S"))
                             + "\n")

    @staticmethod
    def writeAnsweringOfCall(timeOfAnswering):
        phoneCallDiary = open("phoneCallDiary.txt", "a")
        phoneCallDiary.write("\tTime of answering: " + str(timeOfAnswering.strftime("%H:%M:%S")) + "\n")

    @staticmethod
    def writeEndOfCall(timeOfHangingUp):
        phoneCallDiary = open("phoneCallDiary.txt", "a")
        phoneCallDiary.write("\tTime of hanging up: " + str(timeOfHangingUp.strftime("%H:%M:%S")) + "\n")


def initializeProxy():
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO,
                        datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    logging.info(hostname)
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]
    logging.info(ipaddress)
    print("Address of SIP proxy: " + ipaddress)
    global recordroute
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress, PORT)
    global topvia
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress, PORT)
    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()


if __name__ == '__main__':
    startProxy = input("Press Y if you want to start SIP proxy or N if you want to stop the execution. ").upper()
    while startProxy != 'Y' and startProxy != 'N':
        startProxy = input("Press Y if you want to start SIP proxy or N if you want to stop the execution. ").upper()

    try:
        if startProxy == 'Y':
            print("SIP proxy is running.")
            proxy = threading.Thread(target=initializeProxy)
            proxy.start()
            time.sleep(1)

            stopProxy = input("Press Y if you want to stop SIP proxy. ").upper()
            while stopProxy != 'Y':
                stopProxy = input("Press Y if you want to stop SIP proxy. ").upper()

            if stopProxy == 'Y':
                print("Shutdown of SIP proxy")
                raise KeyboardInterrupt

        else:
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
