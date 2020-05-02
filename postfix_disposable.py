#!/usr/bin/env python3

import smtpd
import smtplib
import asyncore


import psycopg2
from hashlib import blake2b
import base64
import re
import sys
import datetime
from email import utils


prefix="dm-"

re_header_end = re.compile(b'\n\n')
re_dkim_sig = re.compile(b'\nDKIM-Signature:')
re_header_field_end = re.compile(b'\n[^ \t]')
re_from_line = re.compile(b'\n[Ff]rom: [^\n]*\n')
re_subject_pattern = re.compile(b'\nSubject: ([^\n]*)\n')


#--------------------------------------------------------------------------------
# read configuration
#--------------------------------------------------------------------------------
def config_help():
	print("Configuration is incomplete.")
	print("Create a file 'disposable_config.py', following the example of example_disposable_config.py")

try:
	from disposable_config import *
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
def create_disposable_alias(token, local_addr, description):
	token = token.lower()
	token_hash, token_h2 = hash_token(token)

	local_hash1 = hash_str(local_addr+secret)[:5]
	local_hash2 = bytes([a ^ b for (a,b) in zip(local_hash1, token_h2)])
	local_hash = b32enc(local_hash2)[:8]

	# # example code for retrieving local hash
	# local_hash2_dec = b32dec(local_hash)
	# local_hash1_dec = bytes([a ^ b for (a,b) in zip(local_hash2_dec, token_h2)])
	# if not local_hash1_dec == local_hash1:
	# 	print("ERROR: "+ b32enc(local_hash1_dec) + "  " + b32enc(local_hash1))
	# else:
	# 	print("Decoding successful")

	sig = version + token_hash + local_hash
	domain = local_addr.split("@")[-1]
	alias = prefix + token + "." + sig + "@" + domain

	with conn.cursor() as cur:
		cur.execute("""
			INSERT INTO disposable_aliases(alias, local, description)
			VALUES(%s, %s, %s)
			ON CONFLICT DO NOTHING
			""",
			[alias, local_addr, description])

	return alias


def delete_disposable_alias(disposable_addr, local_addr):
	with conn.cursor() as cur:
		cur.execute("""
			DELETE FROM disposable_aliases
			WHERE alias = %s AND local = %s
			""",
			[disposable_addr, local_addr])


def normalize_address(addr):
	addr = addr.replace('\'', '')
	addr = addr.replace('\"', '')
	return addr


def check_new_alias(addr_from, addr_to):
	# if recipient starts with prefix
	# add mailfrom to disposable_aliases
	if not addr_to.startswith(prefix):
		return "wrong prefix for " + addr_from

	# extract token and hash for verification
	at_pos = addr_to.rindex("@")
	dot_pos = addr_to.rindex(".", 0, at_pos)

	token = addr_to[len(prefix) : dot_pos]
	sig = addr_to[dot_pos+1 : at_pos]
	token_hash, _ = hash_token(token)

	outsider_hash = sig[len(version):][:len(token_hash)]

	if token_hash != outsider_hash:
		return "wrong hash for " + addr_to + " was " + outsider_hash + " (from signature " + sig + ")" + ", should have been " + token_hash

	# fetch local address
	with conn.cursor() as cur:
		cur.execute("""
			SELECT local FROM disposable_aliases
			WHERE alias = %s
			""", [addr_to])

		row = cur.fetchone()
		if row is None:
			return "alias " + addr_to + " does not exist"
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


def remove_dkim_signature(data):
	"""Removes the field "DKIM-Signature" from the mail header"""
	sep = re_header_end.search(data)
	if not sep:
		sep_pos = len(data)
	else:
		sep_pos = sep.start()
	dkim = re_dkim_sig.search(data)
	if not dkim or dkim.start() > sep_pos:
		return data

	dkim_end = re_header_field_end.search(data, dkim.end())
	if not dkim_end:
		return data

	return data[:dkim.start()] + data[dkim_end.start():]



def rewrite_from_address(data, mailfrom):
	"""Changes the sender of the message"""

	sep = re_header_end.search(data)
	if not sep:
		sep_pos = len(data)
	else:
		sep_pos = sep.start()

	next_start = 0
	count = 0
	while True:
		from_pos = re_from_line.search(data, next_start)
		print("found " + str(from_pos))
		if not from_pos:
			break
		next_start = from_pos.end()
		if next_start > sep_pos:
			break
		count =+ 1

	new_from = b'\nFrom: ' + mailfrom.encode() + b'\n'
	data = re_from_line.sub(new_from, data, count)
	return data


def send_command_reply(addr_from, subject, data):
	message_template="""From: disposable <{addr_from}>
To: {addr_to}
Subject: {subject}
Date: {date}

{body}
"""

	now = datetime.datetime.now()
	date_str = utils.format_datetime(now)

	d = {
		"addr_from": service_addr,
		"addr_to": addr_from,
		"subject": subject,
		"date": date_str,
		"body": data
		}
	message = message_template.format(**d)

	server = smtplib.SMTP('localhost', 10026)
	server.sendmail(addr_from, addr_from, message)
	server.quit()


def list_rindex(lst, item):
	for i in range(len(lst)-1, -1, -1):
		if lst[i] == item:
			return i
	return -1


def handle_command(local_addr, args, body):
	if args[0] == "create":
		reply = "generated aliases:\n"
		for token in args[1:]:
			disp = create_disposable_alias(token, local_addr, body)
			reply += "\n\t" + token + ": " + disp
		reply += "\n"
		return "created addresses", reply


	if args[0] == "register":
		split_idx = list_rindex(args, "for")
		if split_idx < 1:
			return "usage: register <token>... for <external_mail_addr>...", ""

		reply = "generated aliases:\n"
		disp_addrs = []
		for token in args[1:split_idx]:
			disp = create_disposable_alias(token, local_addr, body)
			disp_addrs.append(disp)
			reply += "\n\t" + token + ": " + disp
		reply += "\n\nregistered rewrites:\n"
		for external_mail_addr in args[split_idx+1:]:
			for disp in disp_addrs:
				info = check_new_alias(external_mail_addr, disp)
				reply += "\n\t" + info
		reply += "\n"

		return "registered addresses", reply


	if args[0] == "delete":
		for disposable_addr in args[1:]:
			delete_disposable_alias(disposable_addr, local_addr)
		reply = "\n".join(args[1:])
		return "deleted addresses", reply

	return "unknown command " + args[0], ""


def handle_mail(addr_from, addr_tos, data):
	if service_addr in addr_tos:
		subj_match = re_subject_pattern.search(data)
		subj = subj_match.group(1)
		subj = subj.decode()

		sep = re_header_end.search(data)
		if sep:
			sep_pos = sep.start()
		else:
			sep_pos = 0
		body = data[sep_pos:].decode().strip()
		args = subj.split(" ")
		result = handle_command(addr_from, args, body)
		send_command_reply(local_addr, result[0], result[1])
		return

	# apply transformation for sender
	addr_from = normalize_address(addr_from)
	for addr_to in addr_tos:
		new_addr_from, from_changed = replace_with_disposable(addr_from, addr_to)
		if from_changed:
			addr_from = new_addr_from
			print("rewrote to " + addr_from)
			break

	# register remote address for alias
	for addr_to in addr_tos:
		recipient = normalize_address(addr_to)
		check_new_alias(addr_from, recipient)

	if from_changed:
		data = rewrite_from_address(data, addr_from)

	# remove DKIM signature
	# - if from address has been rewritten, the signature is invalid
	# - if nothing has changed, it would be added again by the milter
	data = remove_dkim_signature(data)
	server = smtplib.SMTP('localhost', 10026)
	server.sendmail(addr_from, addr_tos, data)
	server.quit()


#--------------------------------------------------------------------------------
# internal smtp server
#--------------------------------------------------------------------------------

class DisposableRewriteSMTPServer(smtpd.SMTPServer):

	def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
		try:
			handle_mail(mailfrom, rcpttos, data)
		except:
			print('Undefined exception')
		return

def connect_database():
	global conn
	conn = create_psycopg2_connection()
	conn.set_session(autocommit=True)

	with conn.cursor() as cur:
		cur.execute("""
			CREATE TABLE IF NOT EXISTS disposable_aliases (
				alias varchar(256) NOT NULL,
				local varchar(256) NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				description TEXT NOT NULL,
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


def start_smtp_server():
	server = DisposableRewriteSMTPServer(('127.0.0.1', 10025), None)
	asyncore.loop()
	conn.close()

# # example:
# #
# disp = create_disposable_alias("purpose", "me@example.com")
# print("disposable email address: " + str(disp))
# print("simulate received mail: " + str(check_new_alias("outsider@example.org", disp)))
# print("replying using disposable:   " + str(replace_with_disposable("me@example.com", "outsider@example.org")))
# print("replying without disposable: " + str(replace_with_disposable("me@example.com", "someone-else@example.org")))


if __name__ == '__main__':
	connect_database()

	args = sys.argv[1:]
	if args[0] == "--server":
		start_smtp_server()

	# pipe mode
	if args[0] == "--from":
		addr_from = args[1]
		assert args[2] == "--"
		rcptos = args[3:]

		data = sys.stdin.buffer.read()
		handle_mail(addr_from, rcptos, data)
		conn.close()

	if args[0] == "--manage":
		local_addr = args[1]
		# TODO: description for create
		result = handle_command(local_addr, args[2:], "")
		print(result[0])
		print(result[1])
		conn.close()

# vim: tabstop=4 softtabstop=0 noexpandtab shiftwidth=4 smarttab
