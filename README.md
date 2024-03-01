SMTP Shaper, a SMTP limiter for AlternC.
========================================

This module for AlternC installs a postfix policy daemon for emails sent by a user using SASL.

If the user send more than 1000 emails per hour or 5000 emails per day, or emails from more than 100 different IP in a day, then his/her account is locked, and an email is sent to the administrator of the AlternC account, advising him/her to change his/her passsword.

The account is locked by adding '*' before its password (in the alternc.address MySQL table). Therefore, it's easy to restaure the passowrd, or to know who were blocked that way.

You can setup different shaping values, add emails to send warning to, change the from, in /etc/alternc/smtpshaper.conf ...

Note that you can add keys to the json configuration:

* "mail_sender" is the sender email address,
* "mail_file" is the mail template (first line is the subject, then the rest is the body, and %%HOSTNAME%% %%EMAIL%% %%MESSAGE%% are substituted automatically with contextual values
* "mail_bcc" is an array of recipients to add as blind copy when sending emails.

The email message sent to the user can be changed in /etc/alternc/smtpshaper.*.txt and in the configuration file.

This package is distributed as a debian package at https://debian.alternc.org

License: GPLv3+ (C) AlternC Team 2018-2019

