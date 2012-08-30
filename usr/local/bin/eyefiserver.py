#!/usr/bin/env python
#
# This is a standalone Eye-Fi Server
#
#  Copyright (c) 2009 Jeffrey Tchang
#  Copyright (c) 2010 Pieter van Kemenade
#  Copyright (c) 2011 Jeremy Fitzhardinge
#  Copyright (c) 2011 Grant Nakamura
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

"""
This is a standalone Eye-Fi Server that is designed to take the place of the
Eye-Fi Manager.

Starting this server creates a listener on port 59278. I use the BaseHTTPServer
class included with Python. I look for specific POST/GET request URLs and
execute functions based on those URLs.
"""

# Default is to listen to all addresses on port 59278
# Exemple: SERVER_ADDRESS = '127.0.0.1', 59278
SERVER_ADDRESS = '', 59278

# How many bytes are read at once:
# If the value is too small, non-upload request might fail
# If the value is too big, the progress meter will not be precise
READ_CHUNK_SIZE = 10 * 1024

# KNOW BUGS:
# logger doesn't catch exception from do_POST threads and such.
# So these errors are logged to stderr only, not in log files.
# Prefer stderr for debugging

import sys
import os
import select
import subprocess
import signal
from StringIO import StringIO
import hashlib
import binascii
import struct
import array
import tarfile
from datetime import datetime
import ConfigParser
from optparse import OptionParser
import cgi
import logging
import xml.sax
import xml.dom.minidom
from BaseHTTPServer import BaseHTTPRequestHandler
import BaseHTTPServer
import SocketServer


# Create the main logger
eyeFiLogger = logging.Logger("eyeFiLogger", logging.DEBUG)

# Create two handlers. One to print to the log and one to print to the console
consoleHandler = logging.StreamHandler(sys.stderr)

# Set how both handlers will print the pretty log events
eyeFiLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s")
consoleHandler.setFormatter(eyeFiLoggingFormat)

# Append both handlers to the main Eye Fi Server logger
eyeFiLogger.addHandler(consoleHandler)




def calculateTCPChecksum(buf):
    """
    The TCP checksum requires an even number of bytes. If an even
    number of bytes is not passed in then nul pad the input and then
    compute the checksum
    """

    # If the number of bytes I was given is not a multiple of 2
    # pad the input with a null character at the end
    if len(buf) % 2 != 0:
        buf = buf + "\x00"

    counter = 0
    sumOfTwoByteWords = 0

    # Loop over all the bytes, two at a time
    while counter < len(buf):

        # For each pair of bytes, cast them into a 2 byte integer (unsigned
        # short).
        # Compute using little-endian (which is what the '<' sign if for)
        unsignedShort = struct.unpack("<H", buf[counter:counter+2])

        # Add them all up
        sumOfTwoByteWords = sumOfTwoByteWords + int(unsignedShort[0])
        counter = counter + 2


    # The sum at this point is probably a 32 bit integer. Take the left 16 bits
    # and the right 16 bites, interpret both as an integer of max value 2^16
    # and add them together. If the resulting value is still bigger than 2^16
    # then do it again until we get a value less than 16 bits.
    while sumOfTwoByteWords >> 16:
        sumOfTwoByteWords = (sumOfTwoByteWords >> 16) \
                          + (sumOfTwoByteWords & 0xFFFF) 

    # Take the one's complement of the result through the use of an xor
    checksum = sumOfTwoByteWords ^ 0xFFFFFFFF

    # Compute the final checksum by taking only the last 16 bits
    checksum = checksum & 0xFFFF

    return checksum



def calculateIntegrityDigest(buf, uploadkey):
    """
    Compute a CRC for buf & uploadket
    See IntegrityDigest bellow
    """
    # If the number of bytes I was given is not a multiple of 512
    # pad the input with a null characters to get the proper alignment
    while len(buf) % 512 != 0:
        buf = buf + "\x00"

    counter = 0

    # Create an array of 2 byte integers
    concatenatedTCPChecksums = array.array('H')

    # Loop over all the buf, using 512 byte blocks
    while counter < len(buf): 

        tcpChecksum = calculateTCPChecksum(buf[counter:counter+512])
        concatenatedTCPChecksums.append(tcpChecksum)
        counter = counter + 512

    # Append the upload key
    concatenatedTCPChecksums.fromstring(binascii.unhexlify(uploadkey))

    # Get the concatenatedTCPChecksums array as a binary string
    integrityDigest = concatenatedTCPChecksums.tostring()

    # MD5 hash the binary string
    m = hashlib.md5()
    m.update(integrityDigest)

    # Hex encode the hash to obtain the final integrity digest
    integrityDigest = m.hexdigest()

    return integrityDigest


class EyeFiContentHandler(xml.sax.handler.ContentHandler):
    "Eye Fi XML SAX ContentHandler"

    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)

        # Where to put the extracted values
        self.extractedElements = {}

    def startElement(self, name, attributes):
        self.last_element_name = name

    def characters(self, content):
        self.extractedElements[self.last_element_name] = content


class EyeFiServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    "Implements an EyeFi server"

    def get_request(self):
        connection, address = BaseHTTPServer.HTTPServer.get_request(self)
        eyeFiLogger.debug("Incoming request from client %s", address)
        # It is important to have a non-null timeout because the card will send
        # empty server discovery packets: These are never closed in a proper
        # way, and would stack forever on the server side.
        connection.settimeout(15)
        return connection, address


def build_soap_response(actionname, items):
    """
    Build an SOAP response in EyeFi format:
    actionname is a simple string such as GetPhotoStatusResponse
    items is a list of tupple (key, value)
    """
    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS(
        'http://schemas.xmlsoap.org/soap/envelope/',
        'SOAP-ENV:Envelope')
    SOAPElement.setAttribute(
        'xmlns:SOAP-ENV',
        'http://schemas.xmlsoap.org/soap/envelope/')
    doc.appendChild(SOAPElement)

    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")
    SOAPElement.appendChild(SOAPBodyElement)

    actionElement = doc.createElement(actionname)
    actionElement.setAttribute('xmlns', 'http://localhost/api/soap/eyefilm')
    SOAPBodyElement.appendChild(actionElement)
    # Note that in old version of code, this xmlns attribute was sent only for
    # StartSessionResponse and GetPhotoStatusResponse
    # but not for UploadPhotoResponse nor MarkLastPhotoInRollResponse

    for key, value in items:
        itemElement = doc.createElement(key)
        actionElement.appendChild(itemElement)

        itemElementText = doc.createTextNode(value)
        itemElement.appendChild(itemElementText)
    return doc.toxml(encoding="UTF-8")


class EyeFiRequestHandler(BaseHTTPRequestHandler):
    """This class is responsible for handling HTTP requests passed to it.
    It implements the common HTTP method do_POST()"""


    def split_multipart(self, postdata):
        """
        Takes a EyeFi http posted data
        Returns a dictionnary of multipart/form-data if available
        Otherwise returns returns a dictionary with a single key 'SOAPENVELOPE'
        """
        content_type = self.headers.get('content-type', '')
        if content_type.startswith('multipart/form-data'):
            # content-type header looks something like this
            # multipart/form-data; boundary=---------------------------02468ace13579bdfcafebabef00d
            multipart_boundary = content_type.split('=')[1].strip()
            
            form = cgi.parse_multipart(StringIO(postdata),
                {'boundary': multipart_boundary})
            eyeFiLogger.debug("Available multipart/form-data: %s", form.keys())

            # Keep only the first value for each key
            for key in form.keys():
                form[key] = form[key][0]
            return form
        else:
            return {'SOAPENVELOPE': postdata}


    def do_POST(self):
        """
        That function is called when a HTTP POST request is received.
        """
        # Be somewhat nicer after a real connection has been achieved
        # see EyeFiServer.get_request comments
        self.connection.settimeout(60) 

        # Debug dump request:
        eyeFiLogger.debug("%s %s %s",
                          self.command, self.path, self.request_version)
        eyeFiLogger.debug("Headers received in POST request:")
        for name, value in self.headers.items():
            eyeFiLogger.debug(name + ": " + value)

        # Read at most READ_CHUNK_SIZE bytes of POST data
        content_length = int(self.headers.get("content-length"))
        readsize = min(content_length, READ_CHUNK_SIZE)
        eyeFiLogger.debug("Reading %d bytes of data", readsize)
        postdata = self.rfile.read(readsize)
        if len(postdata) != readsize:
            eyeFiLogger.error('Failed to read %s bytes', readsize)
            self.close_connection = 1
            return

        splited_postdata = self.split_multipart(postdata)
        
        soapenv = splited_postdata['SOAPENVELOPE']
            
        # Delegating the XML parsing of postdata to EyeFiContentHandler()
        handler = EyeFiContentHandler()
        xml.sax.parseString(soapenv, handler)
        soapdata = handler.extractedElements

        # Perform action based on path and soapaction
        if self.path == "/api/soap/eyefilm/v1":
            eyeFiLogger.debug("%s", postdata)

            # Get and normalize soapaction http header
            soapaction = self.headers.get("soapaction", "")
            if soapaction[:5] == '"urn:' and soapaction[-1] == '"':
                soapaction = soapaction[5:-1]
            else:
                eyeFiLogger.error('soapaction should have format "urn:action"')
                self.close_connection = 1
                return
            
            eyeFiLogger.info("Got request %s(%s)", soapaction, ", ".join(
                    ["%s='%s'" % (key, value)
                     for key, value in soapdata.items()]))

            if soapaction == 'StartSession':
                # A soapaction of StartSession indicates the beginning of an
                # EyeFi authentication request
                response = self.startSession(soapdata)

            elif soapaction == 'GetPhotoStatus':
                # GetPhotoStatus allows the card to query if a photo has been
                # uploaded to the server yet
                response = self.getPhotoStatus(soapdata)

            elif soapaction == 'MarkLastPhotoInRoll':
                # If soapaction is MarkLastPhotoInRoll
                response = self.markLastPhotoInRoll(soapdata)

            else:
                eyeFiLogger.error('Unsupported soap action %s', soapaction)
                self.close_connection = 1
                return

            eyeFiLogger.debug("%s response: %s", soapaction, response)

        elif self.path == "/api/soap/eyefilm/v1/upload":
            # If the URL is upload, the card is ready to send a picture to me

            eyeFiLogger.info("Got request UploadPhoto(%s)", ", ".join(
                             ["%s='%s'" % (key, value)
                              for key, value in soapdata.items()]))

            tardata = splited_postdata['FILENAME'] # just the begining

            response = self.uploadPhoto(postdata, soapdata, tardata)
            eyeFiLogger.debug("Upload response: %s", response)

        else:
            logging.error('Unsupported POST request: url="%s"', self.path)
            self.close_connection = 1
            return

        self.send_eyefi_response(response)


    def send_eyefi_response(self, response):
        """
        Sends the response text to the connection in HTTP.
        Close the connection if needed.
        """
        self.send_response(200)
        self.send_header('Date', self.date_time_string())
        self.send_header('Pragma', 'no-cache')
        self.send_header('Server', 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)')
        self.send_header('Content-Type', 'text/xml; charset="utf-8"')
        self.send_header('Content-Length', len(response))
        if self.headers.get('Connection', '') == 'Keep-Alive':
            self.send_header('Connection', 'Keep-Alive')
            eyeFiLogger.debug('Keeping connection alive')
            self.close_connection = 0
        else:
            self.send_header('Connection', 'Close')
            self.close_connection = 1
            eyeFiLogger.debug('Closing connection')
        self.end_headers()

        self.wfile.write(response)
        self.wfile.flush()


    def markLastPhotoInRoll(self, soapdata):
        "Handles MarkLastPhotoInRoll action"

        return build_soap_response('MarkLastPhotoInRollResponse', [])


    def uploadPhoto(self, postdata, soapdata, tardata):
        """
        Handles receiving the actual photograph from the card.
        postdata will most likely contain multipart binary post data that needs to
        be parsed.
        """
        # Here, tardata is only the first bytes of tar file content

        macaddress = soapdata["macaddress"]

        # Get upload_dir
        try:
            upload_dir = self.server.config.get(macaddress, 'upload_dir')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            upload_dir = self.server.config.get('EyeFiServer', 'upload_dir')
        upload_dir = datetime.now().strftime(upload_dir) # resolves %Y and so
        upload_dir = os.path.expanduser(upload_dir) # expands ~

        # Check/create upload_dir
        if not os.path.isdir(upload_dir):
            os.makedirs(upload_dir)
            eyeFiLogger.debug("Generated path %s", upload_dir)
            #if uid!=0 and gid!=0:
            #    os.chown(upload_dir, uid, gid)
            #if mode!="":
            #    os.chmod(upload_dir, string.atoi(mode))

        tarpath = os.path.join(upload_dir, soapdata["filename"])

        tarfilehandle = open(tarpath, 'wb')
        eyeFiLogger.debug("Opened file %s for binary writing", tarpath)

        #if uid!=0 and gid!=0:
        #    os.chown(tarpath, uid, gid)
        #if mode!="":
        #    os.chmod(tarpath, string.atoi(mode))

        
        tarfinalsize = int(soapdata['filesize']) # size to reach

        tarfilehandle.write(tardata)
        tarsize = len(tardata)

        # Read remaining POST data
        content_length = int(self.headers.get("content-length"))
        while len(postdata) < content_length:
            readsize = min(content_length - len(postdata), READ_CHUNK_SIZE)
            start = datetime.utcnow()
            readdata = self.rfile.read(readsize)
            if len(readdata) != readsize:
                eyeFiLogger.error('Failed to read %s bytes', readsize)
                self.close_connection = 1
                return
            elapsed_time = datetime.utcnow() - start
            elapsed_seconds = elapsed_time.days * 86400 \
                            + elapsed_time.seconds \
                            + elapsed_time.microseconds / 1000000.

            # We need to keep a full copy of postdata for integrity
            # verification
            postdata += readdata

            if tarsize < tarfinalsize:
                if tarsize + len(readdata) <= tarfinalsize:
                    tarfilehandle.write(readdata)
                    tarsize += len(readdata)
                else:
                    tarfilehandle.write(readdata[:tarfinalsize-tarsize])
                    tarsize = tarfinalsize

            if elapsed_seconds: # no /0
                eyeFiLogger.debug("%s: Read %s / %s bytes (%02.02f%%) %d kBps",
                    soapdata['filename'],
                    len(postdata),
                    content_length,
                    len(postdata) * 100. / content_length,
                    len(readdata)/elapsed_seconds/1000)


        #pike
        #uid = self.server.config.getint('EyeFiServer', 'upload_uid')
        #gid = self.server.config.getint('EyeFiServer', 'upload_gid')
        #mode = self.server.config.get('EyeFiServer', 'upload_mode')
        #eyeFiLogger.debug("Using uid/gid %d/%d"%(uid, gid))
        #eyeFiLogger.debug("Using mode %s", mode)

        responseElementText = "true"


        tarfilehandle.close()
        eyeFiLogger.debug("Closed file %s", tarpath)


        try:
            integrity_verification = self.server.config.getboolean(
                'EyeFiServer', 'integrity_verification')
        except ConfigParser.NoOptionError:
            integrity_verification = False

        if integrity_verification:
            # Start postdata parsing again, to get INTEGRITYDIGEST key.
            # That key is not available until all of postdata is received
            splited_postdata = self.split_multipart(postdata)

            try:
                upload_key = self.server.config.get(macaddress, 'upload_key')
            except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                upload_key = self.server.config.get('EyeFiServer', 'upload_key')
        
            # Perform an integrity check on the file before writing it out
            verifiedDigest = calculateIntegrityDigest(
                splited_postdata['FILENAME'], upload_key)
            try:
                unverifiedDigest = splited_postdata['INTEGRITYDIGEST']
            except KeyError:
                eyeFiLogger.error("No INTEGRITYDIGEST received.")
            else:
                eyeFiLogger.debug(
                    "Comparing my digest [%s] to card's digest [%s].",
                    verifiedDigest, unverifiedDigest)
                if verifiedDigest == unverifiedDigest:
                    eyeFiLogger.debug("INTEGRITYDIGEST passes test.")
                else:
                    eyeFiLogger.error(
                        "INTEGRITYDIGEST pass failed. File rejected.")
                    responseElementText = "false"


        eyeFiLogger.debug("Extracting TAR file %s", tarpath)
        imageTarfile = tarfile.open(tarpath)
        imagefilename = imageTarfile.getnames()[0]
        imageTarfile.extractall(path=upload_dir)

        eyeFiLogger.debug("Closing TAR file %s", tarpath)
        imageTarfile.close()

        eyeFiLogger.debug("Deleting TAR file %s", tarpath)
        os.remove(tarpath)

        # Run a command on the file if specified
        try:
            execute_cmd = self.server.config.get('EyeFiServer', 'execute')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            execute_cmd = None
        if execute_cmd:
            imagepath = os.path.join(upload_dir, imagefilename)
            eyeFiLogger.debug('Executing command "%s %s"',
                              execute_cmd, imagepath)
            subprocess.Popen([execute_cmd, imagepath])

        return build_soap_response('UploadPhotoResponse', [
            ('success', responseElementText),
            ])


    def getPhotoStatus(self, soapdata):
        "Handles GetPhotoStatus action"
        return build_soap_response('GetPhotoStatusResponse', [
            ('fileid', '1'),
            ('offset','0'),
            ])


    def startSession(self, soapdata):
        "Handle startSession requests"
        macaddress = soapdata['macaddress']
        cnonce = soapdata['cnonce']
        try:
            upload_key = self.server.config.get(macaddress, 'upload_key')
        except ConfigParser.NoSectionError:
            upload_key = self.server.config.get('EyeFiServer', 'upload_key')

        eyeFiLogger.debug("Setting Eye-Fi upload key to %s", upload_key)

        credentialString = macaddress + cnonce + upload_key
        eyeFiLogger.debug("Concatenated credential string (pre MD5): %s",
                          credentialString)

        # Return the binary data represented by the hexadecimal string
        # resulting in something that looks like "\x00\x18V\x03\x04..."
        binaryCredentialString = binascii.unhexlify(credentialString)

        # Now MD5 hash the binary string
        m = hashlib.md5()
        m.update(binaryCredentialString)

        # Hex encode the hash to obtain the final credential string
        credential = m.hexdigest()

        return build_soap_response('StartSessionResponse', [
            ('credential', credential),
            ('snonce', '99208c155fc1883579cf0812ec0fe6d2'),
            ('transfermode', soapdata['transfermode']),
            ('transfermodetimestamp', soapdata['transfermodetimestamp']),
            ('upsyncallowed', 'false'),
            ])


def load_config(conffiles):
    eyeFiLogger.info("Reading config from %s", conffiles)
    config = ConfigParser.RawConfigParser()
    config.read(conffiles)

    # (re)set logger verbosity level
    loglevel = logging.DEBUG
    try:
        loglevel = config.get('EyeFiServer', 'loglevel')
        assert loglevel in \
                ('DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'FATAL'), \
            'Error in conf file: Invalid loglevel'
        loglevel = eval('logging.'+loglevel)
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
        pass
    eyeFiLogger.setLevel(loglevel)

    return config


def main():
    """
    Main function
    """
    parser = OptionParser(usage='%prog [options]')
    parser.add_option('--conf',
        action='append', dest='conffiles', metavar='conffile',
        help='specific alternate location for configuration file. ' \
           + 'default=%default',
        default=['/etc/eyefiserver.conf',
                 os.path.expanduser('~/eyefiserver.conf')])
    parser.add_option('--log', dest='logfile',
        help='log to file')
    options, args = parser.parse_args()

    if args:
        parser.error("That program takes no parameter.")

    # open file logging
    if options.logfile:
        fileHandler = logging.FileHandler(options.logfile, "w", encoding=None)
        fileHandler.setFormatter(eyeFiLoggingFormat)
        eyeFiLogger.addHandler(fileHandler)

    # run webserver as www-data - cant get it working
    #if config.get('EyeFiServer', 'user_id')!='':
    #    os.setuid(config.getint('EyeFiServer', 'user_id'))

    def sighup_handler(signo, frm):
        """
        That function is called on SIGUP and reload the configuration files.
        """
        eyeFiServer.config = load_config(options.conffiles)
    signal.signal(signal.SIGHUP, sighup_handler)

    try:
        # Create an instance of an HTTP server. Requests will be handled
        # by the class EyeFiRequestHandler
        eyeFiServer = EyeFiServer(SERVER_ADDRESS, EyeFiRequestHandler)
        eyeFiServer.config = load_config(options.conffiles)

        eyeFiLogger.info("Eye-Fi server starts listening on port %s",
                         SERVER_ADDRESS[1])
        while True:
            try:
                eyeFiServer.serve_forever()
            except select.error as err:
                if err.args[0] == 4: # system call interrupted by SIGHUP
                    pass # ignore it
                else:
                    raise

    except KeyboardInterrupt:
        eyeFiLogger.info("Eye-Fi server shutting down")
        eyeFiServer.socket.close()
        eyeFiServer.shutdown()
        eyeFiLogger.info("Waiting for threads to finish.")

if __name__ == '__main__':
    main()
