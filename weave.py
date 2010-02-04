#!/usr/bin/python

####################### BEGIN LICENSE BLOCK #############################
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
# the specific language governing rights and limitations under the License.
#
# The Original Code is Weave Python Client.
#
# The Initial Developer of the Original Code is Mozilla Corporation.
# Portions created by the Initial Developer are Copyright (C) 2009 the Initial
# Developer. All Rights Reserved.
#
# Contributor(s):
#  Michael Hanson <mhanson@mozilla.com> (original author)
#
# Alternatively, the contents of this file may be used under the terms of either
# the GNU General Public License Version 2 or later (the "GPL"), or the GNU
# Lesser General Public License Version 2.1 or later (the "LGPL"), in which case
# the provisions of the GPL or the LGPL are applicable instead of those above.
# If you wish to allow use of your version of this file only under the terms of
# either the GPL or the LGPL, and not to allow others to use your version of
# this file under the terms of the MPL, indicate your decision by deleting the
# provisions above and replace them with the notice and other provisions
# required by the GPL or the LGPL. If you do not delete the provisions above, a
# recipient may use your version of this file under the terms of any one of the
# MPL, the GPL or the LGPL.
#
###################### END LICENSE BLOCK ############################

import urllib
import urllib2
import httplib
import hashlib
import logging
import unittest
import base64
import json

opener = urllib2.build_opener(urllib2.HTTPHandler)

class WeaveException(Exception):
	def __init__(self, value):
		self.value = value
		
	def __str__(self):
		return repr(self.value)


############ WEAVE USER API ###############

def createUser(serverURL, userID, password, email, secret = None, captchaChallenge = None, captchaResponse = None):
	"""Create a new user at the given server, with the given userID, password, and email.
	
	If a secret is provided, or a captchaChallenge/captchaResponse pair, those will be provided
	as well.  Note that the exact new-user-authorization logic is determined by the server."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")
	if email.find('"') >=0:
		raise ValueError("Weave email addresses may not contain the quote character")
	if secret and secret.find('"') >=0:
		raise ValueError("Weave secret may not contain the quote character")

	url = serverURL + "/user/1/%s/" % userID

	secretStr = ""
	captchaStr = ""
	if secret:
		secretStr = ''', "secret":"%s"''' % secret

	if captchaChallenge and captchaResponse:
		if secret:
			raise WeaveException("Cannot provide both a secret and a captchaResponse to createUser")
		captchaStr = ''', "captcha-challenge":"%s", "captcha-response":"%s"''' % (captchaChallenge, captchaResponse)

	payload = '''{"password":"%s", "email": "%s"%s%s}''' % (password, email, secretStr, captchaStr)

	req = urllib2.Request(url, data=payload)
	req.get_method = lambda: 'PUT'
	try:
		f = opener.open(req)
		result = f.read()
		if result != userID:
			raise WeaveException("Unable to create new user: got return value '%s' from server" % result)
			
	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		raise WeaveException("Unable to communicate with Weave server: " + str(e) + "; %s" % msg)


def checkNameAvailable(serverURL, userID):
	"""Returns a boolean for whether the given userID is available at the given server."""
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1/%s/" % userID

	req = urllib2.Request(url)
	try:
		f = urllib2.urlopen(req)
		result = f.read()
		if result == "1":
			return False
		elif result == "0":
			return True
		else:
			raise WeaveException("Unexpected return value from server on name-availability request: '%s'" % result)
	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: " + str(e))


def getUserStorageNode(serverURL, userID, password):
	"""Returns the URL representing the storage node for the given user.
	
	Note that in the 1.0 server implementation hosted by Mozilla, the password
	is not actually required for this call."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1/%s/node/weave" % userID


	req = urllib2.Request(url)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)

	try:
		f = opener.open(req)
		result = f.read()
		f.close()
		return result
			
	except urllib2.URLError, e:
		if str(e).find("404") >= 0:
			return serverURL
		else:
			raise WeaveException("Unable to communicate with Weave server: " + str(e))


def changeUserEmail(serverURL, userID, password, newemail):
	"""Change the email address of the given user."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")
	if newemail.find('"') >=0:
		raise ValueError("Weave email addresses may not contain the quote character")

	url = serverURL + "/user/1/%s/email" % userID

	payload = newemail

	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:
		f = opener.open(req)
		result = f.read()
		if result != newemail:
			raise WeaveException("Unable to change user email: got return value '%s' from server" % result)
			
	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



def changeUserPassword(serverURL, userID, password, newpassword):
	"""Change the password of the given user."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1/%s/password" % userID

	payload = newpassword
	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:

		f = opener.open(req)
		result = f.read()
		if result != "success":
			raise WeaveException("Unable to change user password: got return value '%s' from server" % result)
			
	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



def deleteUser(serverURL, userID, password):
	"""Delete the given user."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1/%s/" % userID

	req = urllib2.Request(url)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'DELETE'
	try:
		f = opener.open(req)
		result = f.read()
			
	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		raise WeaveException("Unable to communicate with Weave server: " + str(e) + "; %s" % msg)



def setUserProfile(serverURL, userID, profileField, profileValue):
	"""Experimental: Set a user profile field.  Not part of the 1.0 API."""
	
	if userID.find('"') >=0:
		raise ValueError("Weave userIDs may not contain the quote character")

	url = serverURL + "/user/1/%s/profile" % userID

	payload = newpassword
	req = urllib2.Request(url, data=payload)
	base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
	req.add_header("Authorization", "Basic %s" % base64string)
	req.get_method = lambda: 'POST'
	try:
		f = opener.open(req)
		result = f.read()
		if result != "success":
			raise WeaveException("Unable to change user password: got return value '%s' from server" % result)
			
	except urllib2.URLError, e:
		raise WeaveException("Unable to communicate with Weave server: %s" % e)



class WeaveStorageContext(object):
	"""An object that encapsulates a server, userID, and password, to simplify
	storage calls for the client."""

	def __init__(self, userID, password, rootServer):
		self.url = getUserStorageNode(rootServer, userID, password)
		if self.url[len(self.url)-1] == '/': self.url = self.url[:len(self.url)-1]
		self.userID = userID
		self.password = password
		logging.debug("Created WeaveStorageContext for %s: storage node is %s" % (userID, self.url))
	
	def http_get(self, url):
		return storage_http_op("GET", self.userID, self.password, url)
	
	def add_or_modify_item(self, collection, item, urlID=None, ifUnmodifiedSince=None):
		return add_or_modify_item(self.url, self.userID, self.password, collection, item, urlID=urlID, ifUnmodifiedSince=ifUnmodifiedSince)

	def add_or_modify_items(self, collection, itemArray, ifUnmodifiedSince=None):
		return add_or_modify_items(self.url, self.userID, self.password, collection, itemArray, ifUnmodifiedSince=ifUnmodifiedSince)	

	def delete_item(self, collection, id, ifUnmodifiedSince=None):
		return delete_item(self.url, self.userID, self.password, collection, id, ifUnmodifiedSince=ifUnmodifiedSince)

	def delete_items(self, collection, idArray=None, params=None):
		return delete_items(self.url, self.userID, self.password, collection, idArray=idArray, params=params)

	def delete_items_older_than(self, collection, timestamp):
		return delete_items_older_than(self.url, self.userID, self.password, collection, timestamp)

	def delete_all(self):
		return delete_all(self.url, self.userID, self.password)
			
	def get_collection_counts(self):
		return get_collection_counts(self.url, self.userID, self.password)

	def get_collection_timestamps(self):
		return get_collection_timestamps(self.url, self.userID, self.password)

	def get_collection_ids(self, collection, params=None, asJSON=True, outputFormat=None):
		return get_collection_ids(self.url, self.userID, self.password, collection, params=params, asJSON=asJSON, outputFormat=outputFormat)

	def get_item(self, collection, id, asJSON=True):
		return get_item(self.url, self.userID, self.password, collection, id, asJSON=asJSON, withAuth=True)

	def get_items(self, collection, asJSON=True):
		return get_items(self.url, self.userID, self.password, collection, asJSON=asJSON, withAuth=True)

	def get_quota(self):
		return get_quote(self.url, self.userID, self.password)



def storage_http_op(method, userID, password, url, payload=None, asJSON=True, ifUnmodifiedSince=None, withConfirmation=None, withAuth=True, outputFormat=None):
	"""Generic HTTP helper function.  Sets headers and performs I/O, optionally
	performing JSON parsing on the result."""

	req = urllib2.Request(url, data=payload)
	if withAuth:
		base64string = base64.encodestring('%s:%s' % (userID, password))[:-1]
		req.add_header("Authorization", "Basic %s" % base64string)
	if ifUnmodifiedSince:
		req.add_header("X-If-Unmodified-Since", "%s" % ifUnmodifiedSince)
	if withConfirmation:
		req.add_header("X-Confirm-Delete", "true")
	if outputFormat:
		req.add_header("Accept", outputFormat)
	
	req.get_method = lambda: method

	try:
		logging.debug("Making %s request to %s%s" % (method, url, " with auth %s" % base64string if withAuth else ""))
		f = opener.open(req)
		result = f.read()
		if asJSON:
			return json.loads(result)
		else:
			return result
	except urllib2.URLError, e:
		msg = ""
		try:
			msg = e.read()
		except:
			pass
		# TODO process error code
		logging.debug("Communication error: %s, %s" % (e, msg))
		raise WeaveException("Unable to communicate with Weave server: %s" % e)


def add_or_modify_item(storageServerURL, userID, password, collection, item, urlID=None, ifUnmodifiedSince=None):
	'''Adds the WBO defined in 'item' to 'collection'.  If the WBO does
	not contain a payload, will update the provided metadata fields on an
	already-defined object.
	
	Returns the timestamp of the modification.'''
	if urlID:
		url = storageServerURL + "/1.0/%s/storage/%s/%s" % (userID, collection, urllib.quote(urlID))	
	else:
		url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	if type(item) == str:
		itemJSON = item
	else:
		itemJSON = json.dumps(item)
	return storage_http_op("PUT", userID, password, url, itemJSON, asJSON=False, ifUnmodifiedSince=ifUnmodifiedSince)

def add_or_modify_items(storageServerURL, userID, password, collection, itemArray, ifUnmodifiedSince=None):
	'''Adds all the items defined in 'itemArray' to 'collection'; effectively
	performs an add_or_modifiy_item for each.
	
	Returns a map of successful and modified saves, like this:
	
	{"modified":1233702554.25,
	 "success":["{GXS58IDC}12","{GXS58IDC}13","{GXS58IDC}15","{GXS58IDC}16","{GXS58IDC}18","{GXS58IDC}19"],
	 "failed":{"{GXS58IDC}11":["invalid parentid"],
						 "{GXS58IDC}14":["invalid parentid"],
						 "{GXS58IDC}17":["invalid parentid"],
						 "{GXS58IDC}20":["invalid parentid"]}
	}
	'''
	url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	if type(itemArray) == str:
		itemArrayJSON = itemArray
	else:
		itemArrayJSON = json.dumps(itemArray)
	return storage_http_op("POST", userID, password, url, itemArrayJSON, ifUnmodifiedSince=ifUnmodifiedSince)


def delete_item(storageServerURL, userID, password, collection, id, ifUnmodifiedSince=None):
	"""Deletes the item identified by collection and id."""
	
	url = storageServerURL + "/1.0/%s/storage/%s/%s" % (userID, collection, urllib.quote(id))
	return storage_http_op("DELETE", userID, password, url, ifUnmodifiedSince=ifUnmodifiedSince)

def delete_items(storageServerURL, userID, password, collection, idArray=None, params=None):
	"""Deletes the item identified by collection, idArray, and optional parameters."""
	# TODO: Replace params with named arguments.

	if params:
		if idArray:
			url = storageServerURL + "/1.0/%s/storage/%s?ids=%s&%s" % (userID, collection, urllib.quote(','.join(idArray)), params)
		else:
			url = storageServerURL + "/1.0/%s/storage/%s?%s" % (userID, collection, params)
	else:
		if idArray:
			url = storageServerURL + "/1.0/%s/storage/%s?ids=%s" % (userID, collection, urllib.quote(','.join(idArray)))
		else:
			url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	return storage_http_op("DELETE", userID, password, url)

def delete_items_older_than(storageServerURL, userID, password, collection, timestamp):
	"""Deletes all items in the given collection older than the provided timestamp."""
	url = storageServerURL + "/1.0/%s/storage/%s?older=%s" % (userID, collection, timestamp)
	return storage_http_op("DELETE", userID, password, url)

def delete_all(storageServerURL, userID, password, confirm=True):
	"""Deletes all items in the given collection."""
	# The only reason you'd want confirm=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage" % (userID)
	return storage_http_op("DELETE", userID, password, url, asJSON=False, withConfirmation=confirm)
		
def get_collection_counts(storageServerURL, userID, password):
	"""Returns a map of all collection names and the number of objects in each."""
	url = storageServerURL + "/1.0/%s/info/collection_counts" % (userID)
	return storage_http_op("GET", userID, password, url)

def get_collection_timestamps(storageServerURL, userID, password):
	"""Returns a map of the modified timestamp for each of the collections."""
	url = storageServerURL + "/1.0/%s/info/collections" % (userID)
	return storage_http_op("GET", userID, password, url)

def get_collection_ids(storageServerURL, userID, password, collection, params=None, asJSON=True, outputFormat=None):
	"""Returns a list of IDs for objects in the specified collection."""
	# TODO replace params with named arguments
	if params:
		url = storageServerURL + "/1.0/%s/storage/%s?%s" % (userID, collection, params)
	else:
		url = storageServerURL + "/1.0/%s/storage/%s" % (userID, collection)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, outputFormat=outputFormat)

def get_items(storageServerURL, userID, password, collection, asJSON=True, withAuth=True):
	"""Returns all the items in the given collection."""
	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage/%s?full=1" % (userID, collection)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, withAuth=withAuth)

def get_item(storageServerURL, userID, password, collection, id, asJSON=True, withAuth=True):
	"""Returns the specified item."""
	# The only reason to set withFalse=False is for unit testing
	url = storageServerURL + "/1.0/%s/storage/%s/%s?full=1" % (userID, collection, id)
	return storage_http_op("GET", userID, password, url, asJSON=asJSON, withAuth=withAuth)

def get_quota(storageServerURL, userID, password):
	"Returns an array of [<amount used>,<limit>].  Not implemented by Weave 1.0 production servers."
	url = storageServerURL + "/1.0/%s/info/quota" % (userID)
	return storage_http_op("GET", userID, password, url)


# Crypto implementation:
from PBKDF2 import PBKDF2 
from M2Crypto.EVP import Cipher, RSA, load_key_string
import M2Crypto.m2

class WeaveCryptoContext(object):
	"""Encapsulates the cryptographic context for a user and their collections."""
	
	def __init__(self, storageContext, passphrase):
		self.ctx = storageContext
		self.passphrase = passphrase
		self.privateKey = None
		self.bulkKeys = {}
		self.bulkKeyIVs = {}
	
	def fetchPrivateKey(self):
		"""Fetch the private key for the user and storage context
		provided to this object, and decrypt the private key
		by using my passphrase.  Store the private key in internal
		storage for later use."""
	
		# Retrieve encrypted private key from the server
		logging.debug("Fetching encrypted private key from server")
		privKeyObj = self.ctx.get_item("keys", "privkey")
		payload = json.loads(privKeyObj['payload'])
		self.privKeySalt = base64.decodestring(payload['salt'])
		self.privKeyIV = base64.decodestring(payload['iv'])
		self.pubKeyURI = payload['publicKeyUri']

		data64 = payload['keyData']
		encryptedKey = base64.decodestring(data64)
		
		# Now decrypt it by generating a key with the passphrase
		# and performing an AES-256-CBC decrypt.
		logging.debug("Decrypting encrypted private key")
		
		passKey = PBKDF2(self.passphrase, self.privKeySalt, iterations=4096).read(32)
		cipher = Cipher(alg='aes_256_cbc', key=passKey, iv=self.privKeyIV, op=0) # 0 is DEC
		cipher.set_padding(padding=1)
		v = cipher.update(encryptedKey)
		v = v + cipher.final()
		del cipher
		decryptedKey = v

		# Result is an NSS-wrapped key.
		# We have to do some manual ASN.1 parsing here, which is unfortunate.
		
		# 1. Make sure offset 22 is an OCTET tag; if this is not right, the decrypt
		# has gone off the rails.
		if ord(decryptedKey[22]) != 4:
			logging.debug("Binary layout of decrypted private key is incorrect; probably the passphrase was incorrect.")
			raise ValueError("Unable to decrypt key: wrong passphrase?")

		# 2. Get the length of the raw key, by interpreting the length bytes
		offset = 23
		rawKeyLength = ord(decryptedKey[offset])
		det = rawKeyLength & 0x80
		if det == 0: # 1-byte length
			offset += 1
			rawKeyLength = rawKeyLength & 0x7f
		else: # multi-byte length
			bytes = rawKeyLength & 0x7f
			offset += 1
			
			rawKeyLength = 0
			while bytes > 0:
				rawKeyLength *= 256
				rawKeyLength += ord(decryptedKey[offset])
				offset += 1
				bytes -= 1

		# 3. Sanity check
		if offset + rawKeyLength > len(decryptedKey):
			rawKeyLength = len(decryptedKey) - offset
		
		# 4. Extract actual key
		privateKey = decryptedKey[offset:offset+rawKeyLength]
		
		# And we're done.
		self.privateKey = privateKey
		logging.debug("Successfully decrypted private key")
		
	def fetchBulkKey(self, label):
		"""Given a bulk key label, pull the key down from the network,
		and decrypt it using my private key.  Then store the key
		into self storage for later decrypt operations."""

		# Do we have the key already?
		if label in self.bulkKeys:
			return

		logging.debug("Fetching encrypted bulk key from %s" % label)

		# Note that we do not currently support any authentication model for bulk key
		# retrieval other than the usual weave username-password pair.  To support
		# distributed key models for the more advanced sharing scenarios, we will need
		# to revisit that.
		keyData = self.ctx.http_get(label)
		keyPayload = json.loads(keyData['payload'])
		bulkIV = base64.decodestring(keyPayload['bulkIV'])
				
		keyRing = keyPayload['keyring']
		
		# In a future world where we have sharing, the keys of the keyring dictionary will
		# define public key domains for the symmetric bulk keys stored on the ring.
		# Right now, the first item is always the pubkey of a user, and we just grab the first value.

		# We should really make sure that the key we have here matches the private key
		# we're using to unwrap, or none of this makes sense.
		
		# Now, using the user's private key, we will unwrap the symmetric key.					
		encryptedBulkKey = base64.decodestring(keyRing.items()[0][1])

		# This is analogous to this openssl command-line invocation:
		# openssl rsautl -decrypt -keyform DER -inkey privkey.der -in wrapped_symkey.dat -out unwrapped_symkey.dat
		# 
		# ... except that M2Crypto doesn't have an API for DER importing,
		# so we have to PEM-encode the key (with base64 and header/footer blocks).
		# So what we're actually doing is:
		#
		# openssl rsautl -decrypt -keyform PEM -inkey privkey.pem -in wrapped_symkey.dat -out unwrapped_symkey.dat

		logging.debug("Decrypting encrypted bulk key %s" % label)

		pemEncoded = "-----BEGIN RSA PRIVATE KEY-----\n"
		pemEncoded += base64.encodestring(self.privateKey)
		pemEncoded += "-----END RSA PRIVATE KEY-----\n"

		# Create an EVP, extract the RSA key from it, and do the decrypt
		evp = load_key_string(pemEncoded)
		rsa = M2Crypto.m2.pkey_get1_rsa(evp.pkey)
		rsaObj = RSA.RSA(rsa)
		unwrappedSymKey = rsaObj.private_decrypt(encryptedBulkKey, RSA.pkcs1_padding)
		
		# And save it for later use
		self.bulkKeys[label] = unwrappedSymKey
		self.bulkKeyIVs[label] = bulkIV
		logging.debug("Succesfully decrypted bulk key from %s" % label)
		
	def decrypt(self, encryptedObject):
		"""Given an encrypted object, decrypt it and return the plaintext value.
		
		If necessary, will retrieve the private key and bulk encryption key
		from the storage context associated with self."""

		# Coerce JSON if necessary
		if type(encryptedObject) == str or type(encryptedObject) == unicode:
			encryptedObject = json.loads(encryptedObject)
		
		# An encrypted object has two relevant fields
		encryptionLabel = encryptedObject['encryption']
		ciphertext = base64.decodestring(encryptedObject['ciphertext'])
		
		# Go get the keying infromation if need it
		if self.privateKey == None:
			self.fetchPrivateKey()
		if not encryptionLabel in self.bulkKeys:
			self.fetchBulkKey(encryptionLabel)

		# In case you were wondering, this is the same as this operation at the openssl command line:
		# openssl enc -d -in data -aes-256-cbc -K `cat unwrapped_symkey.16` -iv `cat iv.16`
		
		# Do the decrypt
		logging.debug("Decrypting data record using bulk key %s" % encryptionLabel)
		cipher = Cipher(alg='aes_256_cbc', key=self.bulkKeys[encryptionLabel], iv=self.bulkKeyIVs[encryptionLabel], op=0) # 0 is DEC
		v = cipher.update(ciphertext)
		v = v + cipher.final()
		del cipher
		logging.debug("Successfully decrypted data record")
		return v
		

# Command-Line helper utilities

class TextFormatter(object):
	def format(self, obj):
		self.recursePrint(obj, 0)
		
	def recursePrint(self, obj, depth):
		pad = ''.join([' ' for i in xrange(depth)])

		if type(obj) == dict: # yuck, what's the duck-typing way to check for dictionary protocol?
			for key, value in obj.items():
				if type(value) == unicode or type(value) == str:
					print "%s%s: %s" % (pad, key, value)
				else:
					print "%s%s:" % (pad, key)
					self.recursePrint(value, depth+1)
		# If the object is iterable (and not a string, strings are a special case and don't have an __iter__)
		elif hasattr(obj,'__iter__'):
			for i in obj:
				if depth == 1: print "-----"
				self.recursePrint(i, depth)
		else:
			print "%s%s" % (pad, obj)

		
class XMLFormatter(object):
	def format(self, obj):
		pass

class JSONFormatter(object):
	def format(self, obj):
		print obj


# Begin main: If you're running in library mode, none of this matters.

if __name__ == "__main__":

	import sys
	from optparse import OptionParser

	FORMATTERS = {"text": TextFormatter(), "xml": XMLFormatter(), "json": JSONFormatter() }

	# process arguments
	parser = OptionParser()
	#parser.add_option("-h")
	#parser.add_option("-h", "--help", help="print a detailed help message", action="store_true", dest="help")
	parser.add_option("-u", "--user", help="username", dest="username")
	parser.add_option("-p", "--password", help="password (sent securely to server)", dest="password")
	parser.add_option("-k", "--passphrase", help="passphrase (used locally)", dest="passphrase")
	parser.add_option("-c", "--collection", help="collection", dest="collection")
	parser.add_option("-i", "--id", help="object ID", dest="id")
	parser.add_option("-f", "--format", help="format (default is text; options are text, json, xml)", default="text", dest="format")
	parser.add_option("-K", "--credentialfile", help="get username, password, and passphrase from this credential file (as name=value lines)", dest="credentialfile")
	parser.add_option("-v", "--verbose", help="print verbose logging", action="store_true",dest="verbose")
	# parser.add_option("-I", "--interactive", help="enter interactive mode", action="store_true", default=False, dest="interactive")
	parser.add_option("-s", "--server", help="server URL, if you aren't using services.mozilla.com", dest="server")

	# TODO add support for sort, modified, etc.


	(options, args) = parser.parse_args()

	# {'username': None, 'verbose': True, 'format': 'text', 'passphrase': None, 'password': None, 'interactive': False}

	if options.credentialfile:
		if options.username:
			print "The 'username' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.password:
			print "The 'password' option must not be used when a credential file is provided."
			sys.exit(1)
		if options.passphrase:
			print "The 'passphrase' option must not be used when a credential file is provided."
			sys.exit(1)
		try:
			credFile = open(options.credentialfile, "r")
			for line in credFile:
				if len(line) and line[0] != '#':
					key, value = line.split('=', 1)
					key = key.strip()
					if key == 'username':
						options.username = value.strip()
					elif key == 'password':
						options.password = value.strip()
					elif key == 'passphrase':
						options.passphrase = value.strip()
		except Exception, e:
			import traceback
			traceback.print_exc(e)
			print e
			sys.exit(1)

	if not options.username:
		print "The required 'username' argument is missing.  Use -h for help."
		sys.exit(1)
	if not options.password:
		print "The required 'password' argument is missing.  Use -h for help."
		sys.exit(1)
	if not options.passphrase:
		print "The required 'passphrase' argument is missing.  Use -h for help."
		sys.exit(1)

	formatter = FORMATTERS[options.format]

	if options.verbose:
		logging.basicConfig(level = logging.DEBUG)
	else:
		logging.basicConfig(level = logging.ERROR)

	# Create a storage context: this will control all the sending and retrieving of data from the server
	if options.server:
		rootServer = options.server
	else:
		rootServer="https://auth.services.mozilla.com"

	storageContext = WeaveStorageContext(options.username, options.password, rootServer=rootServer)

	# Create a crypto context: this will encrypt and decrypt data locally
	crypto = WeaveCryptoContext(storageContext, options.passphrase)

	# Now do what the user asked for

	if options.collection:
		if options.id:
			# Single item
			result = storageContext.get_item(options.collection, options.id)
			if len(result['payload']) > 0:
				# Empty length payload is legal: indicates a deleted item
				resultText = json.loads(result['payload'])
				resultObject = json.loads(crypto.decrypt(resultText))
				formatter.format(resultObject)
		else:
			# Collection
			result = storageContext.get_items(options.collection)
			for item in result:
				if len(item['payload']) > 0:
					itemText = json.loads(item['payload'])
					itemObject = json.loads(crypto.decrypt(itemText))
					formatter.format(itemObject)
	else:
		print "No command provided: use -h for help"
		
