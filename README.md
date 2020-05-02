
# postfix-disposable

A postfix filter to fight spam and unsolicited mails. The idea: Use a different mail address every time you enter your mail address in an online form. Postfix-disposable helps you to keep it managable. The email addresses contain a signature. Currently the signature is only used for pre-filtering. In the future it may be used for different features, though.

## Requirements

* postfix
* postgres

## Configuration

1. Copy the files `postfix_disposable.py` to `/etc/postfix/`.
1. Create a file `/etc/postfix/disposable_config.py`, based on `example_disposable_config.py`.
1. Create a file `postfix_pgsql-disposable-alias-maps.cf` based on `postfix_pgsql-disposable-alias-maps.cf.j2`.
1. Add the following block to your `/etc/postfix/master.cf`:

       # disposable mailaddresses
       disposable_server      unix  -       -       n       -       10      smtp
             -o smtp_send_xforward_command=yes
             -o disable_mime_output_conversion=yes

       disposable_pipe        unix  -       n       n       -       10      pipe
             flags=Rq user=vmail:vmail null_sender=
             argv=/etc/postfix/postfix_disposable.py --from ${sender} -- ${recipient}
      
       localhost:10026 inet  n       -       n       -       10      smtpd
             -o content_filter=
             -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
             -o smtpd_authorized_xforward_hosts=127.0.0.0/8

1. Setup the alias maps in `/etc/postfix/main.cf`:

       virtual_alias_maps = <other_alias_maps> pgsql:/etc/postfix/pgsql-disposable-alias-maps.cf

1. Configure a content filter in `/etc/postfix/main.cf`:

       # Disposable mailbox
       content_filter = disposable_pipe:localhost:10025
       receive_override_options = no_address_mappings
       
   You can use `disposable_server` instead of `disposable_pipe`, if you ensure that `python3 /etc/postfix/postfix_disposable.py --server` is executed when the server boots.


# Usage

You can manage the aliases 
* by sending an email with the subject `<command>` to the service address configured in `/etc/postfix/disposable_config.py` (default: `disposable@postfix`) from your email address, or 
* by executing `python3 postfix_disposable.py --manage <your_email_address> <command>` on the server.

The commands:
* `create <token>...`: creates a disposable mail address (for each specified token). The token is a human readable identifier. It will be part of the mail address.
  If an email is received to the disposable mail address, the outsider email address becomes associated with it. If you would reply to the email, your email address will be replaced by the disposable email address.
* `register <token>... for <outsider_email_address>...`: creates one or more disposable mail addresses and associate the outsider email addresses with them. If you send an email to one of the outsider email addresses, your email address will be replaced with the disposable email address. It will appear as if the email has been sent from the disposable email address.
* `delete <disposable_addr>...`: remove the disposable mail addresses

# License

Licensed under the Apache License, Version 2.0
