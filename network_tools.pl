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

# Defense in depth: restrict to characters valid in a hostname/IP.
die "Invalid hostname\n" unless $hostname =~ /\A[A-Za-z0-9.\-]+\z/;

# FIXED: list-form open/pipe bypasses the shell entirely, so $hostname is
# passed as a single argv element rather than being parsed for metacharacters.
my $ping_result = '';
open(my $ping_fh, '-|', 'ping', '-c', '1', $hostname)
    or die "Cannot run ping: $!";
while (my $line = <$ping_fh>) {
    $ping_result .= $line;
}
close($ping_fh);
print "Ping result:\n$ping_result\n";

my $report_file = $cgi->param('report');

# Defense in depth: restrict to a safe filename charset (no path separators)
# and reject ".." outright, since a bare ".." has no slash but still resolves
# to the parent directory once concatenated onto the base path.
die "Invalid report file\n"
    unless $report_file =~ /\A[A-Za-z0-9_.\-]+\z/ && $report_file !~ /\.\./;

# FIXED: list-form system() bypasses the shell entirely, so $report_file is
# passed as a single argv element rather than being interpreted by a shell.
system('cp', '/var/reports/' . $report_file, '/tmp/output.txt');

open(my $fh, '<', '/tmp/output.txt') or die "Cannot open: $!";
while (my $line = <$fh>) {
    print $line;
}
close($fh);
