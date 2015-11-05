#!/usr/bin/perl
use strict;
use warnings;
#use diagnostics;

my %dns = ();

sub block_domain {
    my ($domain) = @_;
    my $p = \%dns;
    my $tail_key, my $tail_hash;
    for my $key (reverse(split(/\./, $domain))) {
	$tail_key = $key;
	$tail_hash = $p;
	if(exists $$p{$key}) {
	    if('*' eq $$p{$key}) {
		return;
	    }
	} else {
	    $$p{$key} = {};
	}
	$p = $$p{$key};    
    }
    $$tail_hash{$tail_key} = '*';
}

sub is_blocked {
    my ($domain) = @_;
    my $p = \%dns;
    for my $key(reverse(split(/\./, $domain))) {
	if(exists $$p{$key}) {
	    if('*' eq $$p{$key}) {
		return 1;
	    }
	    $p = $$p{$key};
	} else {
	    return 0;
	}
    }
}

sub process_hosts_blocked {
    my($filename) = @_;
    open my $host_blocked_file, '<', $filename or die "Could not open $filename\n";
    
    while (my $line = <$host_blocked_file> ) {
	chomp($line);
	block_domain($line);
    }
}

my %access = ();

sub rev_dom {
    my($domain) = @_;
    return join('.', reverse(split(/\./, $domain)));
}

sub process_dns_query_log {
    my($filename) = @_;
    open my $dns_query_log_file, '<', $filename or die "Could not open $filename\n";
    while (my $line = <$dns_query_log_file> ) {
	my @words = split(/query:\s/, $line);
	@words = split(/\s/, $words[1]);
	my $domain = $words[0];
	my @segments = split(/\./, $domain);
	if($#segments gt 1) {
	    #ignore domain names with no dot inside

	    if(!is_blocked($domain)) {
		if(exists($access{$domain})) {
		    $access{$domain}++;
		} else {
		    $access{$domain} = 1;
		}
	    }
	}
    }
    my @sorted_keys = sort {rev_dom($a) cmp rev_dom($b) } keys %access;
    for my $key (@sorted_keys) {
	print("$key $access{$key}\n");
    }
}


my $hosts_blocked = $ARGV[0];
my $dns_query_log = $ARGV[1];
process_hosts_blocked($hosts_blocked);
process_dns_query_log($dns_query_log);

