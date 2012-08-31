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
from datetime import datetime, timedelta
import ConfigParser
from optparse import OptionParser
import cgi
import logging
import xml.sax
import xml.dom.minidom
from BaseHTTPServer import BaseHTTPRequestHandler
import BaseHTTPServer
import SocketServer

# Default is to listen to all addresses on port 59278
# Exemple: SERVER_ADDRESS = '127.0.0.1', 59278
SERVER_ADDRESS = '', 59278

# How many bytes are read at once:
# If the value is too small, non-upload request might fail
# If the value is too big, the progress meter will not be precise
READ_CHUNK_SIZE = 10 * 1024

# Repport download progress every few seconds
PROGRESS_FREQUENCY = timedelta(0, 1)

# The server HTTP header
HTTP_SERVER_NAME = 'Eye-Fi Agent/2.0.4.0 (Windows XP SP2)'

# Format of log messages:
LOG_FORMAT = '[%(asctime)s][%(funcName)s] - %(message)s'

# KNOW BUGS:
# logger doesn't catch exception from do_POST threads and such.
# So these errors are logged to stderr only, not in log files.
# Prefer stderr for debugging
#
# integritydigest verification can be really slow, so that connection
# times out.


# Create the main logger
eyeFiLogger = logging.Logger("eyeFiLogger", logging.DEBUG)



class IntegrityDigestFile(file):
    """
    Wrapper around file object
    All write() calls are used to compute a CRC the Eye-Fi way
    """
    def __init__(self, *args, **kargs):
        file.__init__(self, *args, **kargs)
        # Create an array of 2 byte integers
        self.concatenated_tcp_checksums = array.array('H')
        self.todo_buffer = '' # bytes that weren't used yet

    @staticmethod
    def calculate_tcp_checksum(buf):
        """
        The TCP checksum requires an even number of bytes. If an even
        number of bytes is not passed in then nul pad the input and then
        compute the checksum
        """

        # If the number of bytes I was given is not a multiple of 2
        # pad the input with a null character at the end
        if len(buf) % 2 != 0:
            buf = buf + "\x00"

        sum_of_shorts = 0

        # For each pair of bytes, cast them into a 2 byte integer (unsigned
        # short).
        # Compute using little-endian (which is what the '<' sign if for)
        for ushort in struct.unpack('<' + 'H' * (len(buf)/2), buf):
            # Add them all up
            sum_of_shorts = sum_of_shorts + int(ushort)

        # The sum at this point is probably a 32 bit integer. Take the left 16
        # bits and the right 16 bites, interpret both as an integer of max value
        # 2^16 and add them together. If the resulting value is still bigger
        # than 2^16 then do it again until we get a value less than 16 bits.
        while sum_of_shorts >> 16:
            sum_of_shorts = (sum_of_shorts >> 16) + (sum_of_shorts & 0xFFFF)

        # Take the one's complement of the result through the use of an xor
        checksum = sum_of_shorts ^ 0xFFFFFFFF

        # Compute the final checksum by taking only the last 16 bits
        checksum = checksum & 0xFFFF

        return checksum


    def write(self, buf):
        file.write(self, buf)
        self.todo_buffer += buf
        while (len(self.todo_buffer) > 512):
            tcp_checksum = self.calculate_tcp_checksum(self.todo_buffer[:512])
            self.concatenated_tcp_checksums.append(tcp_checksum)
            self.todo_buffer = self.todo_buffer[512:]


    def getintegritydigest(self, uploadkey):
        """
        Returns Eye-Fi CRC value based on previous write()
        """
        # send the remaining buffer
        tcp_checksum = self.calculate_tcp_checksum(self.todo_buffer)
        self.concatenated_tcp_checksums.append(tcp_checksum)

        # Append the upload key
        binuploadkey = binascii.unhexlify(uploadkey)
        self.concatenated_tcp_checksums.fromstring(binuploadkey)

        # Get the concatenated_tcp_checksums array as a binary string
        integritydigest = self.concatenated_tcp_checksums.tostring()

        # MD5 hash the binary string
        md5 = hashlib.md5()
        md5.update(integritydigest)

        # Hex encode the hash to obtain the final integrity digest
        return md5.hexdigest()



class EyeFiContentHandler(xml.sax.handler.ContentHandler):
    "Eye Fi XML SAX ContentHandler"

    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)
        self.extracted_elements = {} # Where to put the extracted values
        self.last_element_name = ''

    def startElement(self, name, attributes):
        self.last_element_name = name

    def characters(self, content):
        self.extracted_elements[self.last_element_name] = content


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

    soapenv_element = doc.createElementNS(
        'http://schemas.xmlsoap.org/soap/envelope/',
        'SOAP-ENV:Envelope')
    soapenv_element.setAttribute(
        'xmlns:SOAP-ENV',
        'http://schemas.xmlsoap.org/soap/envelope/')
    doc.appendChild(soapenv_element)

    soapbody_element = doc.createElement("SOAP-ENV:Body")
    soapenv_element.appendChild(soapbody_element)

    soapaction_element = doc.createElement(actionname)
    soapaction_element.setAttribute(
        'xmlns',
        'http://localhost/api/soap/eyefilm')
    soapbody_element.appendChild(soapaction_element)

    for key, value in items:
        item_element = doc.createElement(key)
        soapaction_element.appendChild(item_element)

        item_elementtext = doc.createTextNode(value)
        item_element.appendChild(item_elementtext)
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
            # multipart/form-data; boundary=---------------------------02468a...
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
        soapdata = handler.extracted_elements

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
        self.send_header('Server', HTTP_SERVER_NAME)
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


    def uploadPhoto(self, postdata_fragment, soapdata, tardata):
        """
        Handles receiving the actual photograph from the card.
        postdata_fragment will most likely contain multipart binary post data that needs to
        be parsed.
        """
        # Here, tardata is only the first bytes of tar file content

        def uploadphoto_response(success):
            """
            Helper function
            """
            return build_soap_response('UploadPhotoResponse', [
                ('success', success),
                ])

        macaddress = soapdata["macaddress"]

        # Get upload_dir
        try:
            upload_dir = self.server.config.get(macaddress, 'upload_dir')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            upload_dir = self.server.config.get('EyeFiServer', 'upload_dir')
        upload_dir = os.path.expanduser(upload_dir) # expands ~


        # Get date_from_file flag
        use_date_from_file = False
        try:
            use_date_from_file = self.server.config.get(macaddress, 'use_date_from_file')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            try:
                use_date_from_file = self.server.config.get('EyeFiServer', 'use_date_from_file')
            except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                pass

        # if needed, get reference date from the tar fragment
        # This is possible because the tar content is at the begining
        if use_date_from_file:
            imagetarfile = tarfile.open(fileobj=StringIO(tardata))
            tarinfo = imagetarfile.getmembers()[0]
            imageinfo = tarinfo.get_info(encoding=None, errors=None)
            reference_date = datetime.fromtimestamp(imageinfo['mtime'])
        else:
            reference_date = datetime.now()

        # resolves %Y and so inside upload_dir value
        upload_dir = reference_date.strftime(upload_dir)

        # Check/create upload_dir
        if not os.path.isdir(upload_dir):
            os.makedirs(upload_dir)
            eyeFiLogger.debug("Generated path %s", upload_dir)
            #if uid!=0 and gid!=0:
            #    os.chown(upload_dir, uid, gid)
            #if mode!="":
            #    os.chmod(upload_dir, string.atoi(mode))

        tarpath = os.path.join(upload_dir, soapdata["filename"])

        tarfilehandle = IntegrityDigestFile(tarpath, 'wb')
        eyeFiLogger.debug("Opened file %s for binary writing", tarpath)

        #if uid!=0 and gid!=0:
        #    os.chown(tarpath, uid, gid)
        #if mode!="":
        #    os.chmod(tarpath, string.atoi(mode))


        tarfinalsize = int(soapdata['filesize']) # size to reach

        tarfilehandle.write(tardata)
        tarsize = len(tardata)


        
        # Read remaining POST data
        received_length = len(postdata_fragment) # size already read
        content_length = int(self.headers.get("content-length"))
        speedtest_starttime = datetime.utcnow()
        speedtest_startsize = received_length
        while received_length < content_length:
            readsize = min(content_length - received_length, READ_CHUNK_SIZE)
            readdata = self.rfile.read(readsize)
            if len(readdata) != readsize:
                eyeFiLogger.error('Failed to read %s bytes', readsize)
                self.close_connection = 1
                return

            # We need to keep the last received data for integrity verification
            postdata_fragment += readdata
            # keep only the last 2kB
            postdata_fragment = postdata_fragment[-2048:]
            received_length += len(readdata)

            if tarsize < tarfinalsize:
                if tarsize + len(readdata) <= tarfinalsize:
                    tarfilehandle.write(readdata)
                    tarsize += len(readdata)
                else:
                    tarfilehandle.write(readdata[:tarfinalsize-tarsize])
                    tarsize = tarfinalsize

            if datetime.utcnow() - speedtest_starttime > PROGRESS_FREQUENCY:
                elapsed_time = datetime.utcnow() - speedtest_starttime

                elapsed_seconds = elapsed_time.days * 86400 \
                                + elapsed_time.seconds \
                                + elapsed_time.microseconds / 1000000.

                eyeFiLogger.debug("%s: Read %s / %s bytes (%02.02f%%) %d kbps",
                    soapdata['filename'],
                    received_length,
                    content_length,
                    received_length * 100. / content_length,
                    (received_length-speedtest_startsize)/elapsed_seconds/1000*8
                    )
 
                speedtest_starttime = datetime.utcnow()
                speedtest_startsize = tarsize


        #pike
        #uid = self.server.config.getint('EyeFiServer', 'upload_uid')
        #gid = self.server.config.getint('EyeFiServer', 'upload_gid')
        #mode = self.server.config.get('EyeFiServer', 'upload_mode')
        #eyeFiLogger.debug("Using uid/gid %d/%d"%(uid, gid))
        #eyeFiLogger.debug("Using mode %s", mode)

        tarfilehandle.close()
        eyeFiLogger.debug("Closed file %s", tarpath)


        try:
            integrity_verification = self.server.config.getboolean(
                'EyeFiServer', 'integrity_verification')
        except ConfigParser.NoOptionError:
            integrity_verification = False

        if integrity_verification:
            # Parse postdata_fragment to get INTEGRITYDIGEST key.
            splited_postdata = self.split_multipart(postdata_fragment)

            try:
                upload_key = self.server.config.get(macaddress, 'upload_key')
            except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
                upload_key = self.server.config.get('EyeFiServer', 'upload_key')

            # Perform an integrity check on the file
            verified_digest = tarfilehandle.getintegritydigest(upload_key)
            try:
                unverified_digest = splited_postdata['INTEGRITYDIGEST']
            except KeyError:
                eyeFiLogger.error("No INTEGRITYDIGEST received.")
            else:
                eyeFiLogger.debug(
                    "Comparing my digest [%s] to card's digest [%s].",
                    verified_digest, unverified_digest)
                if verified_digest == unverified_digest:
                    eyeFiLogger.debug("INTEGRITYDIGEST passes test.")
                else:
                    eyeFiLogger.error(
                        "INTEGRITYDIGEST pass failed. File rejected.")
                    return uploadphoto_response('false')


        eyeFiLogger.debug("Extracting TAR file %s", tarpath)
        imagetarfile = tarfile.open(tarpath)
        imagefilename = imagetarfile.getnames()[0]
        imagetarfile.extractall(path=upload_dir)

        eyeFiLogger.debug("Closing TAR file %s", tarpath)
        imagetarfile.close()

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

        return uploadphoto_response('true')


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

        credentialstring = macaddress + cnonce + upload_key
        eyeFiLogger.debug("Concatenated credential string (pre MD5): %s",
                          credentialstring)

        # Return the binary data represented by the hexadecimal string
        # resulting in something that looks like "\x00\x18V\x03\x04..."
        binarycredentialstring = binascii.unhexlify(credentialstring)

        # Now MD5 hash the binary string
        md5 = hashlib.md5()
        md5.update(binarycredentialstring)

        # Hex encode the hash to obtain the final credential string
        credential = md5.hexdigest()

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

    # Create two handlers. One to print to the log and one to print to the
    # console
    consolehandler = logging.StreamHandler(sys.stderr)

    # Set how both handlers will print the pretty log events
    loggingformater = logging.Formatter(LOG_FORMAT)
    consolehandler.setFormatter(loggingformater)

    # Append both handlers to the main Eye Fi Server logger
    eyeFiLogger.addHandler(consolehandler)

    # open file logging
    if options.logfile:
        filehandler = logging.FileHandler(options.logfile, "w", encoding=None)
        filehandler.setFormatter(loggingformater)
        eyeFiLogger.addHandler(filehandler)

    # run webserver as www-data - cant get it working
    #if config.get('EyeFiServer', 'user_id')!='':
    #    os.setuid(config.getint('EyeFiServer', 'user_id'))

    def sighup_handler(signo, frm):
        """
        That function is called on SIGUP and reload the configuration files.
        """
        eyefiserver.config = load_config(options.conffiles)
    signal.signal(signal.SIGHUP, sighup_handler)

    try:
        # Create an instance of an HTTP server. Requests will be handled
        # by the class EyeFiRequestHandler
        eyefiserver = EyeFiServer(SERVER_ADDRESS, EyeFiRequestHandler)
        eyefiserver.config = load_config(options.conffiles)

        eyeFiLogger.info("Eye-Fi server starts listening on port %s",
                         SERVER_ADDRESS[1])
        while True:
            try:
                eyefiserver.serve_forever()
            except select.error as err:
                if err.args[0] == 4: # system call interrupted by SIGHUP
                    pass # ignore it
                else:
                    raise

    except KeyboardInterrupt:
        eyeFiLogger.info("Eye-Fi server shutting down")
        eyefiserver.socket.close()
        eyefiserver.shutdown()
        eyeFiLogger.info("Waiting for threads to finish.")

if __name__ == '__main__':
    main()
