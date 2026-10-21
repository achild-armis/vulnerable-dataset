#!/usr/bin/perl
# Fixed: CWE-78 OS Command Injection.
# Inputs are validated against a strict allowlist pattern and commands are
# invoked via the list form of system()/open() so the shell never
# interprets user-supplied metacharacters.
use strict;
use warnings;
use CGI;
use File::Basename;

my $cgi = CGI->new;
print $cgi->header('text/plain');

my $hostname = $cgi->param('host');
die "Invalid hostname\n"
    unless defined $hostname
        && $hostname =~ /^[A-Za-z0-9][A-Za-z0-9.-]*$/;

my $ping_result = '';
open(my $ping_fh, '-|', 'ping', '-c', '1', $hostname) or die "Cannot run ping: $!";
{
    local $/;
    $ping_result = <$ping_fh>;
}
close($ping_fh);
print "Ping result:\n$ping_result\n";

my %ALLOWED_REPORTS = (
    'daily_summary.txt'  => 1,
    'weekly_summary.txt' => 1,
    'incident_log.txt'   => 1,
);

my $report_file = $cgi->param('report');
die "Invalid report name\n"
    unless defined $report_file
        && $report_file =~ /^[A-Za-z0-9._-]+$/;
my $safe_report = basename($report_file);
die "Report not allowed\n" unless $ALLOWED_REPORTS{$safe_report};

system('cp', "/var/reports/$safe_report", '/tmp/output.txt') == 0
    or die "Cannot copy report: $?";

open(my $fh, '<', '/tmp/output.txt') or die "Cannot open: $!";
while (my $line = <$fh>) {
    print $line;
}
close($fh);
