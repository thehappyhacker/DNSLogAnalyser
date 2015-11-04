#!/usr/bin/perl
use strict;
use warnings;

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
	$p = \%{$$p{$key}};    
    }
    $$tail_hash{$tail_key} = '*';
}

sub check_if_blocked {
    my ($domain) = @_;
    my $p = \%dns;
    for my $key(reverse(split(/\./, $domain))) {
	if(exists $$p{$key}) {
	    if('*' eq $$p{$key}) {
		return 1;
	    }
	    $p = \%{$$p{$key}};
	} else {
	    return 0;
	}
    }
}

block_domain('ad.net');
block_domain('www.bad.net');
block_domain('bad.net');



my @doms = ('ad.net', '2.ad.net', 'good.net');
for my $dom (@doms) {
    if(check_if_blocked($dom)) {
	print "$dom is blocked\n";
    } else {
	print "$dom is not blocked\n";
    }
} 
