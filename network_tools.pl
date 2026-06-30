#!/usr/bin/perl
# CWE-78: OS Command Injection
# Vulnerable: user-supplied CGI parameters passed directly to the shell
# via backticks and system(), a classic legacy-Perl-CGI pattern.
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;
print $cgi->header('text/plain');

my $hostname = $cgi->param('host');

# VULNERABLE: backtick execution with unsanitized user input allows
# shell metacharacters (;, |, &&) to chain arbitrary commands.
my $ping_result = `ping -c 1 $hostname`;
print "Ping result:\n$ping_result\n";

my $report_file = $cgi->param('report');

# VULNERABLE: system() called with a single concatenated string forces
# shell interpretation of the unsanitized $report_file value.
system("cat /var/reports/" . $report_file . " > /tmp/output.txt");

open(my $fh, '<', '/tmp/output.txt') or die "Cannot open: $!";
while (my $line = <$fh>) {
    print $line;
}
close($fh);
