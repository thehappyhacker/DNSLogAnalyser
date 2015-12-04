#!/usr/bin/perl
use strict;
no warnings;
#use warnings;
#use diagnostics;
#use re 'debug';
use 5.10.0;

my %dns = ();
my %local_name_cache = ('127.0.0.1' => 'localhost');

my $VALID_DOMAIN_REGEX = qr /((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-])*[A-Za-z0-9]))$/o;
my $DOMAIN_REGEX =       qr /(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+(([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-])*[A-Za-z0-9])/o;
my $EXTRACT_DOMAIN_REGEX = qr /query:\s(${DOMAIN_REGEX})\sIN\sA/o;
my $EXTRACT_IP = qr /^(.+)\sclient\s(\d+\.0\.0\.\d+)#\d+:.+query:\s(.+)\sIN A.+/o;
my $REMOVE_END_DOT = qr /^(.+)\.$/o;

my $COMMENT_REGEX = qr /^\s*#/o;

sub block_domain {
    my ($domain) = @_;
    my $p = \%dns;
    my $tail_key, my $tail_hash = $p;
    for my $key (reverse(split(/\./, $domain))) {
	$tail_key = $key;
	$tail_hash = $p;
	if(exists $$p{$key}) {
	    if('*' eq $$p{$key}) {
		say STDERR "Domain $domain already blocked.";
		return;
	    }
	} else {
	    $$p{$key} = {};
	}
	$p = $$p{$key};    
    }
    if($tail_key) {
	$$tail_hash{$tail_key} = '*';
    }
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

    open my $host_blocked_file, '<', $filename or die "Could not open blocked hosts file [$filename]\n";
    
    while (my $line = <$host_blocked_file> ) {
	$line =~ /$COMMENT_REGEX/ and next;
	$line =~ /$VALID_DOMAIN_REGEX/ and block_domain($1);
    }
    close $host_blocked_file;
}

my %access = ();

sub reverse_domain {
    my($domain) = @_;
    return join('.', reverse(split(/\./, $domain)));
}

sub process_dns_query_log {
    my($filename, @params) = @_;
    my($sort_order) = @params;

    say STDERR "Processing query log file: [$filename]";
    open my $dns_query_log_file, '<', $filename or die "Could not open query log file [$filename]\n";
    while (my $line = <$dns_query_log_file> ) {
	$line =~ /$EXTRACT_DOMAIN_REGEX/;
	my $domain = $1;
	if(! $domain) {
	    next;
	}
	if(!is_blocked($domain)) {
	    if(exists($access{$domain})) {
		$access{$domain}++;
	    } else {
		$access{$domain} = 1;
	    }
	}
    }
    my @sorted_keys;
    if($sort_order eq 'access') {
	@sorted_keys = sort { $access{$b} <=> $access{$a} } keys %access;
    } else {
	@sorted_keys = sort {reverse_domain($a) cmp reverse_domain($b) } keys %access;
    }
    for my $key (@sorted_keys) {
	say "$key $access{$key}";
    }
}

sub serialize_blocked_domains_rec {
    my($result, $tree, $path) = @_;
    $path = $path && "$path.";
    for my $key (keys %$tree) {
	$key or die "empty key in dns cache.\n";
	if($$tree{$key} eq '*') {
	    push @$result, "$path$key";
	} else {
	    serialize_blocked_domains_rec($result, $$tree{$key}, "$path$key");
	}
    }
}

sub serialize_blocked_domains() {
    my @block_list = ();
    serialize_blocked_domains_rec(\@block_list, \%dns, '');
    @block_list = sort(@block_list);

    map $_ = reverse_domain($_), @block_list;
    return @block_list;
}

sub list_blocked_domains {
    my ($filename) = @_;
    say STDERR "Generating hosts blocked file: [$filename]";
    open my $OUTPUT, '>', $filename or die "Could not open blocked domains file [$filename]\n";

    my @domains = serialize_blocked_domains;
    for my $dom (@domains) {
	say $OUTPUT $dom;
    }

    close $OUTPUT;
}

sub add_domain {
    my (@domains) = @_;
    for my $domain (@domains) {
	$domain =~ /$VALID_DOMAIN_REGEX/ or die "Invalid domain name: [$domain]\n";
	block_domain $domain;
    }
}

sub generate_zone {
    my ($filename) = @_;
    say STDERR "Generating zone.adblock file [$filename]";

    open my $OUTPUT, '>', $filename or die "Could not open zone output file [$filename]\n";
    
    my @domains = serialize_blocked_domains;
    for my $domain (@domains) {
	say $OUTPUT qq(zone "$domain" { type master; file "/etc/bind/ionescu/adblock/db.adblock"; };);
    }
    close $OUTPUT;
}

sub filter {
    my(@params) = @_;
    while(my $line = <STDIN>) {
	$line =~ /$EXTRACT_DOMAIN_REGEX/;
	my $domain = $1;
	if(! $domain) {
	    next;
	}
	if(is_blocked($domain)) {
	    say "blocked: $domain";
	} else {
	  #  say $line;
	    $line =~ /$EXTRACT_IP/;
	    my $time = $1;
	    my $ip = $2;
	    my $remote_host = $3;
	    my $local_name = $local_name_cache{$ip};
	    if(! $local_name) {
		$local_name = `dig +short -x $ip`;
		if($local_name) {
		    $local_name =~ /$REMOVE_END_DOT/;
		    $local_name = $1;
		    $local_name_cache{$ip} = $local_name;
		} else {
		    $local_name = $ip;
		}
	    }
	    say "$time client: $local_name, query: $remote_host";


	}
    }
}

sub help {
	    say STDERR "  Usage:";
	    say STDERR "    $0 <blocked_hosts_file.txt> <domains.blocked> <dnsquery.log> <zones.adblock> help|simplify|processlog|add|generatezone|addgen";
	    say "";
	    say "    Files are identified by extension.";
	    say "    The first non file parameter is the command. All following parameters are command parameters."
}

sub main {
    my $hosts_blocked = "hosts_blocked.txt";
    my $domains_blocked;
    my $zones_file = "zones.adblock";
    my $dns_query_log = "";
    my $command;
    my @params = ();
    for my $e (@ARGV) {
	given($e) {
	    when (/\.txt$/i) { $hosts_blocked = $e; }
	    when (/\.blocked$/i) { $domains_blocked  = $e; }
	    when (/\.log$/i) { $dns_query_log = $e; }
	    when (/\.adblock/) { $zones_file = $e; }
	    default { 
		if(!$command) {
		    $command = $e;
		} else {
		    push @params, $e;
		}
	    }
	}
    }

    process_hosts_blocked($hosts_blocked);
    $domains_blocked and process_hosts_blocked($domains_blocked);


    given($command) {
	when ($_ eq "help" || $_ eq "?") { help; }
	when("processlog") { process_dns_query_log $dns_query_log, @params; }
	when("simplify") { list_blocked_domains $hosts_blocked; }
	when("add") {
	    add_domain @params;
	    list_blocked_domains $hosts_blocked;
	}
	when("generatezone") {
	    generate_zone $zones_file;
	}
	when("addgen") {
	    add_domain @params;
	    list_blocked_domains $hosts_blocked;
	    generate_zone $zones_file;
	}
	when("filter") {
	    filter @params;
	}
	default { help; }
    }
}

main;
