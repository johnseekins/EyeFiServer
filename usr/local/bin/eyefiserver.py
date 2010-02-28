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
This is a standalone Eye-Fi Server that is designed to take the place of the Eye-Fi Manager.

Starting this server creates a listener on port 59278. I use the BaseHTTPServer class included
with Python. I look for specific POST/GET request URLs and execute functions based on those
URLs.
"""

# KNOW BUGS:
# logger doesn't catch exception from do_POST threads and such.
# So these errors are logged to stderr only, not in log files.
# Prefer stderr for debugging

import sys
import os
import socket
import StringIO
import hashlib
import binascii
import struct
import array
import tarfile
from datetime import datetime
import ConfigParser
import cgi
import logging
import xml.sax
from xml.sax.handler import ContentHandler
import xml.dom.minidom
from BaseHTTPServer import BaseHTTPRequestHandler
import BaseHTTPServer
import SocketServer


# Create the main logger
eyeFiLogger = logging.Logger("eyeFiLogger", logging.DEBUG)

# Create two handlers. One to print to the log and one to print to the console
consoleHandler = logging.StreamHandler(sys.stdout)

# Set how both handlers will print the pretty log events
eyeFiLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s")
consoleHandler.setFormatter(eyeFiLoggingFormat)

# Append both handlers to the main Eye Fi Server logger
eyeFiLogger.addHandler(consoleHandler)




def calculateTCPChecksum(bytes):
  """
  The TCP checksum requires an even number of bytes. If an even
  number of bytes is not passed in then nul pad the input and then
  compute the checksum
  """

  # If the number of bytes I was given is not a multiple of 2
  # pad the input with a null character at the end
  if len(bytes) % 2 != 0:
    bytes = bytes + "\x00"
      
  counter = 0
  sumOfTwoByteWords = 0
      
  # Loop over all the bytes, two at a time
  while counter < len(bytes):
  
    # For each pair of bytes, cast them into a 2 byte integer (unsigned short)
    # Compute using little-endian (which is what the '<' sign if for)
    unsignedShort = struct.unpack("<H", bytes[counter:counter+2])
    
    # Add them all up
    sumOfTwoByteWords = sumOfTwoByteWords + int(unsignedShort[0])
    counter = counter + 2

  
  # The sum at this point is probably a 32 bit integer. Take the left 16 bits
  # and the right 16 bites, interpret both as an integer of max value 2^16 and
  # add them together. If the resulting value is still bigger than 2^16 then do it
  # again until we get a value less than 16 bits.
  while sumOfTwoByteWords >> 16:
    sumOfTwoByteWords = (sumOfTwoByteWords >> 16) + (sumOfTwoByteWords & 0xFFFF) 
  
  # Take the one's complement of the result through the use of an xor
  checksum = sumOfTwoByteWords ^ 0xFFFFFFFF

  # Compute the final checksum by taking only the last 16 bits
  checksum = (checksum & 0xFFFF)
  
  return checksum



def calculateIntegrityDigest(bytes, uploadkey):

    # If the number of bytes I was given is not a multiple of 512
    # pad the input with a null characters to get the proper alignment
    while len(bytes) % 512 != 0:
      bytes = bytes + "\x00"
      
    counter = 0
    
    # Create an array of 2 byte integers
    concatenatedTCPChecksums = array.array('H')
    
    # Loop over all the bytes, using 512 byte blocks
    while counter < len(bytes): 
      
      tcpChecksum = calculateTCPChecksum(bytes[counter:counter+512])
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


class EyeFiContentHandler(ContentHandler):
  "Eye Fi XML SAX ContentHandler"

  def __init__(self):
    ContentHandler.__init__(self)
  
    # Where to put the extracted values
    self.extractedElements = {}

  def startElement(self, name, attributes):
    self.last_element_name = name

  def characters(self, content):
    self.extractedElements[self.last_element_name] = content



class EyeFiServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  "Implements an EyeFi server"

  def server_bind(self):

    BaseHTTPServer.HTTPServer.server_bind(self)
    self.socket.settimeout(None)
    self.run = True

  def get_request(self):
    while self.run:
      try:
        connection, address = self.socket.accept()
        eyeFiLogger.debug("Incoming request from client %s", address[0])

        connection.settimeout(None)
        return (connection, address)

      except socket.timeout:
        pass

  #def stop(self):
  #  self.run = False

  # alt serve_forever method for python <2.6
  # because we want a shutdown mech ..
  #def serve(self):
  #  while self.run:
  #    self.handle_request()
  #  self.socket.close()




class EyeFiRequestHandler(BaseHTTPRequestHandler):
  """This class is responsible for handling HTTP requests passed to it.
  It implements the two most common HTTP methods, do_GET() and do_POST()"""

  def do_GET(self):
    eyeFiLogger.debug("%s %s %s", self.command, self.path, self.request_version)

    SOAPAction = self.headers.get("soapaction", "")

    # couldnt get this to work ..
    #if((self.client_address == "localhost") and (self.path == "/api/soap/eyefilm/v1x") and (SOAPAction == "\"urn:StopServer\"")):
    #  eyeFiLogger.debug("Got StopServer request .. stopping server")
    #  self.server.stop()
    # or, for python 2.6>
    #  self.server.shutdown()

    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    # I should be sending a Content-Length header with HTTP/1.1 but I am being lazy
    # self.send_header('Content-length', '123')
    self.end_headers()
    self.wfile.write(self.client_address)
    self.wfile.write(self.headers)
    self.close_connection = 0


  def do_POST(self):
    eyeFiLogger.debug("%s %s %s", self.command, self.path, self.request_version)

    # Debug dump headers
    eyeFiLogger.debug("Headers received in POST request:")
    for name, value in self.headers.items():
        eyeFiLogger.debug(name + ": " + value)

    # Read POST data
    contentLength = int(self.headers.get("content-length"))
    eyeFiLogger.debug("Attempting to read %d bytes of data", contentLength)
    start = datetime.utcnow()
    postData = self.rfile.read(contentLength)
    elapsed_time = datetime.utcnow() - start
    elapsed_seconds = elapsed_time.days * 86400 \
                    + elapsed_time.seconds \
                    + elapsed_time.microseconds / 1000000.
    eyeFiLogger.debug("Finished reading %d bytes of data in %f seconds",
                      len(postData), elapsed_seconds)
    if elapsed_seconds: # no /0
      eyeFiLogger.debug("Speed was %d kBps", len(postData)/elapsed_seconds/1000)

    # TODO: What if len(postData) <> contentLength
    # TODO: Implement some kind of visual progress bar
    # bytesRead = 0
    # postData = ""

    # while(bytesRead < contentLength):
    #  postData = postData + self.rfile.read(1)
    #   bytesRead = bytesRead + 1

    #  if(bytesRead % 10000 == 0):
    #    print "#",


    # Perform action based on path and SOAPAction
    SOAPAction = self.headers.get("soapaction", "")

    if self.path == "/api/soap/eyefilm/v1" and SOAPAction == '"urn:StartSession"':
      # A SOAPAction of StartSession indicates the beginning of an EyeFi
      # authentication request
      eyeFiLogger.debug("Got StartSession request %s", postData)
      response = self.startSession(postData)
      eyeFiLogger.debug("StartSession response: %s", response)

    # GetPhotoStatus allows the card to query if a photo has been uploaded
    # to the server yet
    elif self.path == "/api/soap/eyefilm/v1" and SOAPAction == '"urn:GetPhotoStatus"':
      eyeFiLogger.debug("Got GetPhotoStatus request %s", postData)
      response = self.getPhotoStatus(postData)
      eyeFiLogger.debug("GetPhotoStatus response: %s", response)

    # If the URL is upload and there is no SOAPAction the card is ready to send a picture to me
    elif self.path == "/api/soap/eyefilm/v1/upload" and not SOAPAction:
      eyeFiLogger.debug("Got upload request")
      response = self.uploadPhoto(postData)
      eyeFiLogger.debug("Upload response: %s", response)

    # If the URL is upload and SOAPAction is MarkLastPhotoInRoll
    elif self.path == "/api/soap/eyefilm/v1" and SOAPAction == '"urn:MarkLastPhotoInRoll"':
      eyeFiLogger.debug("Got MarkLastPhotoInRoll request %s", postData)
      response = self.markLastPhotoInRoll(postData)
      eyeFiLogger.debug("MarkLastPhotoInRoll response: %s", response)

    else:
      logging.warning('Unsupported POST request: url="%s" SOAPAction="%s"',
        self.path, SOAPAction)
      return

    self.send_eyefi_response(response)

  def send_eyefi_response(self, response):
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


  def markLastPhotoInRoll(self, postData):
    "Handles MarkLastPhotoInRoll action"
    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

    markLastPhotoInRollResponseElement = doc.createElement("MarkLastPhotoInRollResponse")

    SOAPBodyElement.appendChild(markLastPhotoInRollResponseElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")


  def uploadPhoto(self, postData):
    """Handles receiving the actual photograph from the card.
    postData will most likely contain multipart binary post data that needs to be parsed"""

    # Take the postData string and work with it as if it were a file object
    postDataInMemoryFile = StringIO.StringIO(postData)

    # Get the content-type header which looks something like this
    # content-type: multipart/form-data; boundary=---------------------------02468ace13579bdfcafebabef00d
    contentTypeHeader = self.headers.getheaders('content-type').pop()
    eyeFiLogger.debug(contentTypeHeader)

    # Extract the boundary parameter in the content-type header
    headerParameters = contentTypeHeader.split(";")
    eyeFiLogger.debug(headerParameters)

    boundary = headerParameters[1].split("=")
    boundary = boundary[1].strip()
    eyeFiLogger.debug("Extracted boundary: %s", boundary)

    # eyeFiLogger.debug("uploadPhoto postData: %s", postData)

    # Parse the multipart/form-data
    form = cgi.parse_multipart(postDataInMemoryFile, {"boundary":boundary, "content-disposition":self.headers.getheaders('content-disposition')})
    eyeFiLogger.debug("Available multipart/form-data: %s", form.keys())

    # Parse the SOAPENVELOPE using the EyeFiContentHandler()
    soapEnvelope = form['SOAPENVELOPE'][0]
    eyeFiLogger.debug("SOAPENVELOPE: %s", soapEnvelope)
    handler = EyeFiContentHandler()
    xml.sax.parseString(soapEnvelope, handler)

    eyeFiLogger.debug("Extracted elements: %s", handler.extractedElements)

    macaddress = handler.extractedElements["macaddress"]
    try:
      upload_key = self.server.config.get(macaddress, 'upload_key')
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
      upload_key = self.server.config.get('EyeFiServer', 'upload_key')
    imageTarfileName = handler.extractedElements["filename"]

    #pike
    #uid = self.server.config.getint('EyeFiServer', 'upload_uid')
    #gid = self.server.config.getint('EyeFiServer', 'upload_gid')
    #mode = self.server.config.get('EyeFiServer', 'upload_mode')
    #eyeFiLogger.debug("Using uid/gid %d/%d"%(uid, gid))
    #eyeFiLogger.debug("Using mode %s", mode)

    responseElementText = "true"

    try:
        integrity_verification = self.server.config.getboolean('EyeFiServer', 'integrity_verification')
    except ConfigParser.NoOptionError:
        integrity_verification = False

    if integrity_verification:
        # Write the newly uploaded file to memory
        untrustedFile = StringIO.StringIO()
        untrustedFile.write(form['FILENAME'][0])

        # Perform an integrity check on the file before writing it out
        verifiedDigest = calculateIntegrityDigest(untrustedFile.getvalue(), upload_key)
        try:
          unverifiedDigest = form['INTEGRITYDIGEST'][0]
        except KeyError:
          eyeFiLogger.error("No INTEGRITYDIGEST received.")
        else:
          eyeFiLogger.debug("Comparing my digest [%s] to card's digest [%s].",
            verifiedDigest, unverifiedDigest)
          if verifiedDigest == unverifiedDigest:
            eyeFiLogger.debug("INTEGRITYDIGEST passes test.")
          else:
            eyeFiLogger.error("Digests do not match. Check upload_key setting in .conf file.")
            responseElementText = "false"

    now = datetime.now()
    try:
        uploadDir = now.strftime(self.server.config.get('EyeFiServer', 'upload_dir'))
    except ConfigParser.NoSectionError:
        uploadDir = now.strftime(self.server.config.get(macaddress, 'upload_dir'))

    uploadDir = os.path.expanduser(uploadDir) # expands ~
    if not os.path.isdir(uploadDir):
       os.makedirs(uploadDir)
       #if uid!=0 and gid!=0:
       #  os.chown(uploadDir, uid, gid)
       #if mode!="":
       #  os.chmod(uploadDir, string.atoi(mode))

    imageTarPath = os.path.join(uploadDir, imageTarfileName)
    eyeFiLogger.debug("Generated path %s", imageTarPath)


    fileHandle = open(imageTarPath, 'wb')
    eyeFiLogger.debug("Opened file %s for binary writing", imageTarPath)

    fileHandle.write(form['FILENAME'][0])
    eyeFiLogger.debug("Wrote file %s", imageTarPath)

    fileHandle.close()
    eyeFiLogger.debug("Closed file %s", imageTarPath)

    #if uid!=0 and gid!=0:
    #  os.chown(imageTarPath, uid, gid)
    #if mode!="":
    #  os.chmod(imageTarPath, string.atoi(mode))

    eyeFiLogger.debug("Extracting TAR file %s", imageTarPath)
    imageTarfile = tarfile.open(imageTarPath)
    imageTarfile.extractall(path=uploadDir)

    eyeFiLogger.debug("Closing TAR file %s", imageTarPath)
    imageTarfile.close()

    eyeFiLogger.debug("Deleting TAR file %s", imageTarPath)
    os.remove(imageTarPath)

    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

    uploadPhotoResponseElement = doc.createElement("UploadPhotoResponse")
    successElement = doc.createElement("success")
    successElementText = doc.createTextNode(responseElementText)

    successElement.appendChild(successElementText)
    uploadPhotoResponseElement.appendChild(successElement)

    SOAPBodyElement.appendChild(uploadPhotoResponseElement)
    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")


  def getPhotoStatus(self, postData):
    handler = EyeFiContentHandler()
    xml.sax.parseString(postData, handler)

    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")

    getPhotoStatusResponseElement = doc.createElement("GetPhotoStatusResponse")
    getPhotoStatusResponseElement.setAttribute("xmlns", "http://localhost/api/soap/eyefilm")

    fileidElement = doc.createElement("fileid")
    fileidElementText = doc.createTextNode("1")
    fileidElement.appendChild(fileidElementText)

    offsetElement = doc.createElement("offset")
    offsetElementText = doc.createTextNode("0")
    offsetElement.appendChild(offsetElementText)

    getPhotoStatusResponseElement.appendChild(fileidElement)
    getPhotoStatusResponseElement.appendChild(offsetElement)

    SOAPBodyElement.appendChild(getPhotoStatusResponseElement)

    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")


  def startSession(self, postData):
    # Delegating the XML parsing of startSession postData to EyeFiContentHandler()
    handler = EyeFiContentHandler()
    xml.sax.parseString(postData, handler)

    eyeFiLogger.debug("Extracted elements: %s", handler.extractedElements)

    macaddress =  handler.extractedElements["macaddress"]
    cnonce = handler.extractedElements["cnonce"]
    try:
      upload_key = self.server.config.get(macaddress, 'upload_key')
    except ConfigParser.NoSectionError:
      upload_key = self.server.config.get('EyeFiServer', 'upload_key')

    eyeFiLogger.debug("Setting Eye-Fi upload key to %s", upload_key)

    credentialString = macaddress + cnonce + upload_key
    eyeFiLogger.debug("Concatenated credential string (pre MD5): %s", credentialString)

    # Return the binary data represented by the hexadecimal string
    # resulting in something that looks like "\x00\x18V\x03\x04..."
    binaryCredentialString = binascii.unhexlify(credentialString)

    # Now MD5 hash the binary string
    m = hashlib.md5()
    m.update(binaryCredentialString)

    # Hex encode the hash to obtain the final credential string
    credential = m.hexdigest()

    # Create the XML document to send back
    doc = xml.dom.minidom.Document()

    SOAPElement = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "SOAP-ENV:Envelope")
    SOAPElement.setAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/")
    SOAPBodyElement = doc.createElement("SOAP-ENV:Body")


    startSessionResponseElement = doc.createElement("StartSessionResponse")
    startSessionResponseElement.setAttribute("xmlns", "http://localhost/api/soap/eyefilm")

    credentialElement = doc.createElement("credential")
    credentialElementText = doc.createTextNode(credential)
    credentialElement.appendChild(credentialElementText)

    snonceElement = doc.createElement("snonce")
    snonceElementText = doc.createTextNode("99208c155fc1883579cf0812ec0fe6d2")
    snonceElement.appendChild(snonceElementText)

    transfermodeElement = doc.createElement("transfermode")
    transfermodeElementText = doc.createTextNode(handler.extractedElements["transfermode"])
    transfermodeElement.appendChild(transfermodeElementText)

    transfermodetimestampElement = doc.createElement("transfermodetimestamp")
    transfermodetimestampElementText = doc.createTextNode(handler.extractedElements["transfermodetimestamp"])
    transfermodetimestampElement.appendChild(transfermodetimestampElementText)

    upsyncallowedElement = doc.createElement("upsyncallowed")
    upsyncallowedElementText = doc.createTextNode("false")
    upsyncallowedElement.appendChild(upsyncallowedElementText)


    startSessionResponseElement.appendChild(credentialElement)
    startSessionResponseElement.appendChild(snonceElement)
    startSessionResponseElement.appendChild(transfermodeElement)
    startSessionResponseElement.appendChild(transfermodetimestampElement)
    startSessionResponseElement.appendChild(upsyncallowedElement)

    SOAPBodyElement.appendChild(startSessionResponseElement)

    SOAPElement.appendChild(SOAPBodyElement)
    doc.appendChild(SOAPElement)

    return doc.toxml(encoding="UTF-8")


def main():

  if len(sys.argv) != 3:
    print "usage: %s configfile logfile" % os.path.basename(sys.argv[0])
    sys.exit(2)

  configfile = sys.argv[1]
  eyeFiLogger.info("Reading config %s", configfile)

  config = ConfigParser.SafeConfigParser()
  config.read(configfile)

  # open file logging
  logfile = sys.argv[2]
  fileHandler = logging.FileHandler(logfile, "w", encoding=None)
  fileHandler.setFormatter(eyeFiLoggingFormat)
  eyeFiLogger.addHandler(fileHandler)


  try:
    server_ip = config.get('EyeFiServer','host_name')
  except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
    host_name = ''
  try:
    server_port = config.getint('EyeFiServer','host_port')
  except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
    server_port = 59278
  server_address = server_ip, server_port

  # run webserver as www-data - cant get it working
  #if config.get('EyeFiServer', 'user_id')!='':
  #  os.setuid(config.getint('EyeFiServer', 'user_id'))

  try:
    # Create an instance of an HTTP server. Requests will be handled
    # by the class EyeFiRequestHandler
    eyeFiServer = EyeFiServer(server_address, EyeFiRequestHandler)
    eyeFiServer.config = config

    # Spawn a new thread for the server
    # thread.start_new_thread(eyeFiServer.serve, ())

    eyeFiLogger.info("Eye-Fi server started listening on port %s", server_address[1])
    eyeFiServer.serve_forever()

    #raw_input("\nPress <RETURN> to stop server\n")
    #eyeFiServer.stop()
    #eyeFiLogger.info("Eye-Fi server stopped")
    #eyeFiServer.socket.close()

  except KeyboardInterrupt:
    eyeFiServer.socket.close()
    #eyeFiServer.shutdown()

  #eyeFiLogger.info("Eye-Fi server stopped")

if __name__ == '__main__':
    main()

# vi: set ts=2 et:
