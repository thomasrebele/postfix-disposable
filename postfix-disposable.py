#!/usr/bin/env python3

import smtpd
import smtplib
import asyncore


import psycopg2
from hashlib import blake2b
import base64
import re
import sys

prefix="dm-"

#--------------------------------------------------------------------------------
# read configuration
#--------------------------------------------------------------------------------
def config_help():
	print("Configuration is incomplete.")
	print("Create a file 'secret_config.py', following the example of example_secret_config.py")

try:
	from secret_config import *
	create_psycopg2_connection
	secret

except:
	config_help()
	sys.exit(1)


#--------------------------------------------------------------------------------
# define helper methods
#--------------------------------------------------------------------------------

def b32enc(data):
	result = base64.b32encode(data).decode('ascii')
	return result.lower()

def b32dec(text):
	result = base64.b32decode(text.upper())
	return result

def hash_data(data):
	return blake2b(data).digest()

def hash_str(text):
	return hash_data(text.encode('utf8'))

def hash_token(token):
	token_h = hash_str(token+secret)
	token_h1 = token_h[:5]
	token_h2 = token_h[5:10]
	token_hash = b32enc(token_h1)[:8]
	return token_hash, token_h2


#--------------------------------------------------------------------------------
# helper methods
#--------------------------------------------------------------------------------

# format of disposable alias:
# <prefix><token>.<signature>@<local-domain>
# where
# - prefix: defined in this script
# - token: defined by the user to associate a meaning to the address, max length: 254 - 19 - len(prefix)
# - a dot: separator so that the length of the signature could be determined from the address
# - signature: consists of <version><token-hash><token+local-hash>
#   - version (2-byte): indicate the version of the alias format (allows to change the secret)
#   - token-hash (8-byte): a hash from the token to quickly verify the validity of the alias
#   - local-hash (8-byte): allow multiple users
version = b32enc(b'\x00')[:2]
def create_disposable_alias(token, local):
	token = token.lower()
	token_hash, token_h2 = hash_token(token)

	local_hash1 = hash_str(local+secret)[:5]
	local_hash2 = bytes([a ^ b for (a,b) in zip(local_hash1, token_h2)])
	local_hash = b32enc(local_hash2)[:8]

	# example code for retrieving local hash
	local_hash2_dec = b32dec(local_hash)
	local_hash1_dec = bytes([a ^ b for (a,b) in zip(local_hash2_dec, token_h2)])
	if not local_hash1_dec == local_hash1:
		print("ERROR: "+ b32enc(local_hash1_dec) + "  " + b32enc(local_hash1))
	else:
		print("Decoding successful")

	sig = version + token_hash + local_hash
	domain = local.split("@")[-1]
	alias = prefix + token + "." + sig + "@" + domain

	with conn.cursor() as cur:
		cur.execute("""
			INSERT INTO disposable_aliases(alias, local)
			VALUES(%s, %s)
			ON CONFLICT DO NOTHING
			""",
			[alias, local])

	return alias



def normalize_address(addr):
	addr = addr.replace('\'', '')
	addr = addr.replace('\"', '')
	return addr


def check_new_alias(addr_from, addr_to):
	# if recipient starts with prefix
	# add mailfrom to disposable_aliases
	if not addr_to.startswith(prefix):
		return

	# extract token and hash for verification
	at_pos = addr_to.rindex("@")
	dot_pos = addr_to.rindex(".", 0, at_pos)

	token = addr_to[len(prefix) : dot_pos]
	sig = addr_to[dot_pos+1 : at_pos]
	token_hash, _ = hash_token(token)

	outsider_hash = sig[1:len(token_hash)+1]

	if token_hash != outsider_hash:
		return

	# fetch local address
	with conn.cursor() as cur:
		cur.execute("""
			SELECT local FROM disposable_aliases
			WHERE alias = %s
			""", [addr_to])

		row = cur.fetchone()
		if row is None:
			return
	local = row[0]

	# register
	with conn.cursor() as cur:
		cur.execute("""
			INSERT INTO disposable_links(local, remote, alias)
			VALUES (%s, %s, %s)
			ON CONFLICT DO NOTHING
			""", [local, addr_from, addr_to])

	return "registered rewrite " + local + " -> " + addr_to + " for " + addr_from

def replace_with_disposable(addr_from, addr_to):
	with conn.cursor() as cur:
		cur.execute("""
			SELECT alias FROM disposable_links
			WHERE local = %s AND remote = %s
			""", [addr_from, addr_to])
		row = cur.fetchone()
		if row is None:
			return addr_from, False
		return row[0], True



header_body_sep = re.compile(b'\n\n')
from_line = re.compile(b'\n[Ff]rom: [^\n]*\n')
def rewrite_from_address(data, mailfrom):
	"""Changes the sender of the message"""

	sep = header_body_sep.search(data)
	if not sep:
		sep_pos = len(data)
	else:
		sep_pos = sep.start()

	next_start = 0
	count = 0
	while True:
		from_pos = from_line.search(data, next_start)
		print("found " + str(from_pos))
		if not from_pos:
			break
		next_start = from_pos.end()
		if next_start > sep_pos:
			break
		count =+ 1

	new_from = b'\nFrom: ' + mailfrom.encode() + b'\n'
	return from_line.sub(new_from, data, count)


#--------------------------------------------------------------------------------
# internal smtp server
#--------------------------------------------------------------------------------

class DisposableRewriteSMTPServer(smtpd.SMTPServer):

	def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
		try:
			# apply transformation for sender
			mailfrom = normalize_address(mailfrom)
			for addr_to in rcpttos:
				new_mailfrom, from_changed = replace_with_disposable(mailfrom, addr_to)
				if from_changed:
					mailfrom = new_mailfrom
					print("rewrote to " + mailfrom)
					break

			# register remote address for alias
			for addr_to in rcpttos:
				recipient = normalize_address(addr_to)
				check_new_alias(mailfrom, recipient)

			if from_changed:
				data = rewrite_from_address(data, mailfrom)

			server = smtplib.SMTP('localhost', 10026)
			server.sendmail(mailfrom, rcpttos, data)
			server.quit()

		except:
			print('Undefined exception')

		return

# # example:
# #
# disp = create_disposable_alias("purpose", "me@example.com")
# print("disposable email address: " + str(disp))
# print("simulate received mail: " + str(check_new_alias("outsider@example.org", disp)))
# print("replying using disposable:   " + str(replace_with_disposable("me@example.com", "outsider@example.org")))
# print("replying without disposable: " + str(replace_with_disposable("me@example.com", "someone-else@example.org")))

if __name__ == '__main__':
	conn = create_psycopg2_connection()
	conn.set_session(autocommit=True)

	with conn.cursor() as cur:
		cur.execute("""
			CREATE TABLE IF NOT EXISTS disposable_aliases (
				alias varchar(256) NOT NULL,
				local varchar(256) NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				PRIMARY KEY (alias)
			)
			""")

		cur.execute("""
			CREATE TABLE IF NOT EXISTS disposable_links (
				local varchar(256) NOT NULL,
				remote varchar(256) NOT NULL,
				alias varchar(256) NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				PRIMARY KEY (local, remote)
			)
			""")

	server = DisposableRewriteSMTPServer(('127.0.0.1', 10025), None)
	asyncore.loop()
	conn.close()


# vim: tabstop=4 softtabstop=0 noexpandtab shiftwidth=4 smarttab
