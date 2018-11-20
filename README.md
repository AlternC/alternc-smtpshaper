This is SMTP Shaper, a smtp limiter for AlternC.

This module for AlternC installs a postfix policy daemon for emails sent by a user using SASL.

If the user send more than 1000 emails per hour or 5000 emails per day
or emails from more than 100 different IP in a day
then his/her account is locked, and an email is sent to the administrator of the AlternC account, advising him/her to change his/her passsword.

You can setup different shaping values, add emails to send warning to, change the from, in /etc/alternc/smtpshaper.conf
Email message sent to the user can be changed in /etc/alternc/smtpshaper.*.txt and in the configuration file.

