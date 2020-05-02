import psycopg2

secret="USE YOUR OWN PASSPHRASE"
service_addr="disposable@postfix"

def create_psycopg2_connection():
    return psycopg2.connect(host="127.0.0.1", dbname="mailserver", user="mailuser", password="DB-PASSWORD")
