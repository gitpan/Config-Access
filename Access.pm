#
# Access.pm
#
# Provide access control similar to the hosts_access(5) format used by
# TCP wrappers program by Wietse Venema <wietse@wsv.win.tue.nl>. The
# access control language is similar to the hosts_access format and
# retains many similarities.
#
# The access information is stored in two files.  The <prefix>.allow
# file contains a list of service/client entries that are explicitly
# allowed, and the <prefix>.deny file contains service/client entries
# that are explicitly denied.
#
# Each entry in the access configuration files is of the format below
#
#     service_list : client_list
#
# where service_list is a comma separated list of arbitrary service
# names, and client_list is a comma separated list of arbitrary client
# names.  Queries are made for a single service/client pair which
# returns true if the client is permitted to use the service, false
# otherwise. 
#
# Please send comments/suggestions to Tim.Potter@anu.edu.au.
#
# $Id: Access.pm,v 1.8 1998/08/31 04:04:08 tpot Exp $
#

#
# Copyright (c) 1995,1996,1997,1998 ANU and CSIRO on behalf of the
# participants in the CRC for Advanced Computational Systems ('ACSys').
#
# ACSys makes this software and all associated data and documentation
# ('Software') available free of charge for non-commercial purposes only.
# You may make copies of the Software but you must include all of this notice
# on any copy.
#
# The Software was developed for research purposes and ACSys does not warrant
# that it is error free or fit for any purpose.  ACSys disclaims any
# liability for all claims, expenses, losses, damages and costs any user may
# incur as a result of using, copying or modifying the Software.
#

package Config::Access;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

my $myclass;
BEGIN {
    $myclass = __PACKAGE__;
    $VERSION = "0.01";
}
sub Version () { "$myclass v$VERSION" }

BEGIN {
    @ISA = qw(Exporter);

# Items to export into callers namespace by default
# (move infrequently used names to @EXPORT_OK below)

    @EXPORT = qw(
    );

# Other items we are prepared to export if requested

    @EXPORT_OK = qw(MATCH_SPECIFIC
		    MATCH_ALL
		    MATCH_FALLTHRU
		    MATCH_NET_MASK
    );

# Tags:

    %EXPORT_TAGS = (
    ALL         => [@EXPORT, @EXPORT_OK],
);

}

# Constants for match type

sub MATCH_ALL      { 1; }     # Match made using an ALL clause
sub MATCH_SPECIFIC { 2; }     # Specific service/client match
sub MATCH_FALLTHRU { 3; }     # Allowed because fell through
sub MATCH_NET_MASK { 4; }     # Matched using network/netmask number

# Return a line from the config file.  Support continuation onto the
# next line by the a backslash at the end of the line.

sub read_a_line (*$)
{
    my($FH) = @_;

    # Check for end of file condition

    return undef, if (eof($FH));

    # Read a line

    my($result);
    while(1) {
	$result .= <$FH>;
	chomp($result);

	@_[1]++;        # Increment line number

	last, if !(substr($result, length($result) - 1) eq "\\");
	$result = substr($result, 0, length($result) - 1);
    }

    return $result;
}

# Read allow file

sub parse_file ($$)
{
    my($filename) = @_;

    open(F, "< $filename") || return undef;

    my($line, $linenum);
    while (defined($line = read_a_line(\*F, $linenum))) {

	# Ignore comments

	if ($line =~ /^[ \t]*\#/ or $line =~ /^\s*$/) {
	    next;
	}

	# Grab a line

	if ($line =~ /^\s*(.+)\s*:\s*(.+)$/) {
	    my($daemon_list, $client_list) = ($1, $2);

	    # Fill in entries in rules hash

	    my($i, $j);
	    foreach $i (split(/,\s+/, $daemon_list)) {

		# TODO: syntax check for net/mask format

		foreach $j (split(/,\s+/, $client_list)) {
		    ${@_[1]}{$i}{$j} = 1;
		}
	    }
	} else {
	    print("syntax error in $filename:$linenum\n");
	    return undef;
	}
    }
    close(F);
    return 1;
}

# Convert an IP address in dotted-quad notation into an integer

sub get_raw_ip($)
{
    my($ip) = @_;

    my($num);
    $num = my($n1, $n2, $n3, $n4) = $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;

    if ($num == 4) {
	return $n4 + $n3 * 0x100 + $n2 * 0x10000 + $n1 * 0x1000000;
    } else {
	return undef;
    }
}

# Return a list containing the network number and netmask number
# converted from a string argument.

sub get_net_mask ($)
{
    my($netmask) = @_;

    $netmask =~ /^(\d+\.\d+\.\d+\.\d+)\/(\d+\.\d+\.\d+\.\d+)$/;

    my($net, $mask) = ($1, $2);

    if (!defined($net) or !defined($mask)) {
	return undef;
    } else {
	return (get_raw_ip($net), get_raw_ip($mask));
    }
}

# Check for an exact client match in a rules hash.  Note that we check
# for network/netmask format for the service.

sub pair_present ($$%)
{
    my($service, $client, %rules_hash) = @_;

    # Check for exact match

    if (defined($rules_hash{$service}{$client})) {
	return 1;
    }

    # Match service name as net/mask number
	
    while(my($key, $value) = each(%rules_hash)) {
	my($s_net, $s_mask) = get_net_mask($key);

	if (defined($s_net) and defined($s_mask)) {
	    if ((get_raw_ip($service) & $s_mask) == $s_net) {
	    
		# Check for exact match with client

		if (defined(${$value}{$client})) {
		    return 1;
		}
	    }
	}
    }

    # No match

    return undef;
}

# Check for a network/netmask client match in a rules hash.

sub pair_present_net_mask ($$%)
{
    my($service, $client, %rules_hash) = @_;

    while(my($key, $value) = each(%rules_hash)) {

	# Match service name exactly

	if ($key eq $service) {
	    my($realkey);

	    # Iterate over all clients for this service

	    foreach $realkey (keys(%{$value})) {

		my($c_net, $c_mask) = get_net_mask($realkey);

		# We are checking a service name against an IP address
		
		if (defined($c_net) and defined($c_mask) and 
		    defined(get_raw_ip($client))) {

		    if ((get_raw_ip($client) & $c_mask) == $c_net) {
			return 1;
		    }
		}
	    }

	    # If we are here then no match was found

	    return undef;
	}

	# Match service name as net/mask number
	
	my($s_net, $s_mask) = get_net_mask($key);

	if (defined($s_net) and defined($s_mask)) {
	    if ((get_raw_ip($service) & $s_mask) == $s_net) {

		# Iterate over all clients for this service

		my($realkey);
		foreach $realkey (keys(%{$value})) {
		    
		    my($c_net, $c_mask) = get_net_mask($realkey);

		    # We are checking a service name against an IP address
		
		    if (defined($c_net) and defined($c_mask) and
			(defined(get_raw_ip($client)))) {

			if ((get_raw_ip($client) & $c_mask) == $c_net) {
			    return 1;
			}
		    }
		}
		
		# If we are here then no match was found

		return undef;
	    }
	}
    }
    
    # No match

    return undef;
}

# Make an access query

sub access_query
{
    my($self) = shift;
    my($service, $client) = @_;

    if ($self->{"debug"}) {
	print("access query $service/$client\n");
    }

    #
    # Process allow rules
    #

    # Grant access if match specifically in allow rules

    if (pair_present($service, $client, %{$self->{rules_allow}})) {

	# Allowed specifically

	if ($self->{"debug"}) {
	    print("Allowed $service/$client using specific rule\n");
	}

	@_[2] = MATCH_SPECIFIC;

	return 1;
    }

    # Check for match using ALL clause

    if (pair_present("ALL", "ALL", %{$self->{rules_allow}}) or
	pair_present("ALL", $client, %{$self->{rules_allow}}) or 
	pair_present($service, "ALL", %{$self->{rules_allow}})) {
	
	# Allowed via an "ALL" clause								      
	if ($self->{"debug"}) {
	    print("Allowed $service/$client using ALL rule\n");
	}

	@_[2] = MATCH_ALL;

	return 1;
    }

    # Try to find match using network/netmask numbers

    if (pair_present_net_mask($service, $client, %{$self->{rules_allow}})) {

	# Allowed using network/netmask rule

	if ($self->{"debug"}) {
	    print("Allowed $service/$client using network/netmask rule\n");
	}

	@_[2] = MATCH_NET_MASK;
	return 1;
    }

    #
    # Process deny rules
    #
    
    # Deny access if match specifically in deny rules

    if (pair_present($service, $client, %{$self->{rules_deny}})) {
	
	# Denied specifically

	if ($self->{"debug"}) {
	    print("Denied $service/$client using specific rule\n");
	}

	@_[2] = MATCH_SPECIFIC;

	return undef;
    }

    # Check for match using ALL clause

    if (pair_present("ALL", "ALL", %{$self->{rules_deny}}) or
	pair_present("ALL", $client, %{$self->{rules_deny}}) or
	pair_present($service, "ALL", %{$self->{rules_deny}})) {
	
	# Denied via an "ALL" clause

	if ($self->{"debug"}) {
	    print("Denied $service/$client using ALL rule\n");
	}

	@_[2] = MATCH_ALL;

	return undef;
    }

    # Try to find match using network/netmask numbers

    if (pair_present_net_mask($service, $client, %{$self->{rules_deny}})) {

	# Denied using network/netmask rule

	if ($self->{"debug"}) {
	    print("Denied $service/$client using network/netmask rule\n");
	}

	@_[2] = MATCH_NET_MASK;
	return undef;
    }

    #
    # Else allow access
    #

    if ($self->{"debug"}) {
	print("Allowed $service/$client fell through\n");
    }

    @_[2] = MATCH_FALLTHRU;

    return 1;
}

# The new() method creates a new access object.  The base name for the
# configuration files is passed as a parameter to which ".allow" and
# ".deny" is appended.

sub new
{
    my($this, $prefix, $debug) = @_;

    my($class) = ref($this) || $this;
    my($self) = {};

    # Object variables

    $self->{"debug"} = $debug;

    # Parse config files

    if (!defined(parse_file($prefix . ".allow", \%{$self->{rules_allow}})) or
	!defined(parse_file($prefix . ".deny", \%{$self->{rules_deny}}))) {
	
	return undef;
    }

    # Print access list

    if ($self->{"debug"}) {
	my($i, $j);
	print("Access control list for $prefix\n\n");
	foreach $i (keys(%{$self->{rules_allow}})) {
	    foreach $j (keys(%{$self->{rules_allow}{$i}})) {
		print("allow $i to $j\n");
	    }
	}
	foreach $i (keys(%{$self->{rules_deny}})) {
	    foreach $j (keys(%{$self->{rules_deny}{$i}})) {
		print("deny $i to $j\n");
	    }
	}
	print("\n");
    }

    return bless($self, $class);
}

# Module return value

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

C<Config::Access> - Perform simple access control

=head1 SYNOPSIS

    use strict;                  # not optional (-:
    use Config::Access;

=head1 DESCRIPTION

The C<Config::Access> module provides a method of authenticating
arbitrary client/service pairs in a way very similar to that provided
by the TCP wrappers by Wietse Venema E<lt>wietse@wzv.win.tue.nlE<gt>.

This module can be useful for restricting access to certain parts of a
script to a certain domain.  For example, a front end program to some
device might deny certain users access to certain commands or only
allow trusted users access to dangerous commands.

The access control language is very similar to the access control
language specified in hosts_access(5) for the TCP wrappers.  Two
configuration files specify access rules.  A file ending in .allow
specifies rules to allow access and a file ending in .deny specifies
rules to deny access.  The prefix of these files is specified when a
C<Config::Access> object is created.

=head1 ACCESS CONTROL FILES

As per the TCP wrappers, a request for authorisation consults the
.allow and .deny files.  The search stops at the first match.

=over

=item * Access is granted if a $client/$service matches a rule in the
.allow file.

=item * Access is denied if a $client/$service matches a rule in the
.deny file.

=item * Otherwise, if no match is made access is granted.

=back

=head1 ACCESS CONTROL RULES

Access control rules appear in the configuration files in the
following format.  

    service_list : client_list

Each item in a list is separated by a comma and optional whitespace. 
Newlines and lines beginning with a '#' character are ignored.  A line
may be continued if a backslash character is present as the end of the
line. 

A service or client may be specified as the string 'ALL' which means
it will be matched by anything.  An optional parameter to the
C<access_query> method described below allows the caller to determine
whether the request was granted (or denied) using a rule containing
the ALL wildcard.

C<Config::Access> also supports IP address matching of clients and
services using the network/netmask number format.

The EXCEPT operator present in the TCP wrappers access control
language is not supported.

=head2 Public Methods

=over

=item new

Usage:
	
    $obj = new Config::Access($prefix);
    $obj = new Config::Access($prefix, $debug);
    $obj = 'Config::Access'->new($prefix);
    $obj = 'Config::Access'->new($prefix, $debug);

Returns a newly-initialised C<Config::Access> object.  The configuration
files are read and parsed.  The allow and deny configuration file
names are generated from the prefix argument by appending the string
'C<.allow>' and 'C<.deny>' to the prefix, respectively.

If the $debug parameter is true, then debugging information will be
printed to standard output.  A list of all access rules will be
printed when a C<Config::Access> object is created and a line will be
printed for each invocation of the C<access_query()> method.

=item access_query

Usage:

    $result = $obj->access_query($service, $client);

Perform an access query for the specified $service/$client pair.  The
return value is true if access to the service is allowed for the
client, and undefined otherwise.

    $result = $obj->access_query($service, $client, $mtype);

Perform an access query for the $service/$client pair and return the
match type for the client in the $mtype parameter.  The match type
refers to the type of rule that allowed or denied the match for the
client and can take the following values.

=over

=item MATCH_SPECIFIC

The match was made to a directly specified rule in either the allow or
deny file without using the ALL wildcard.

=item MATCH_NET_MASK

The match was made using a network/netmask pair.

=item MATCH_ALL

The match was made using a rule containing the ALL wildcard.

=item MATCH_FALLTHRU

No matches were made in either the allow or deny file and the match
fell through.

=back

=head2 Exports

=over

=item default

none

=item exportable

C<MATCH_SPECIFIC> C<MATCH_ALL> C<MATCH_FALLTHRU> C<MATCH_NET_MASK>

=item tags

none

=back

=head1 EXAMPLE

The following scripts form a simple example of using the
C<Config::Access> module.  The access controls for the example
correspond to the "mostly closed" model of the TCP wrappers.

  cat > test.pl << 'EOF'
  #!/usr/bin/perl

  use strict;
  use Config::Access;

  my($access) = Config::Access->new("example");
  my($user) = getpwuid($UID);

  if (!$access->access_query("beans", $user)) {
      print("Access to service 'beans' denied for user ", $user, "\n");
  }

  if ($access->access_query("ham", $user)) {
      print("Access to service 'ham' allowed for user ", $user, "\n");
  }
  EOF

  cat > example.allow << 'EOF'
  # Example allow file.  Allow all users to service 'ham' and only
  # selected users to service 'beans'.
  beans: tpot, markus
  ham: ALL
  EOF

  cat > example.deny << 'EOF'
  # Example deny file.  Deny all clients access to all services unless
  # specifically allowed above.
  ALL: ALL
  EOF

=head1 COPYRIGHT

C<Config::Access> is a side-effect of a project at work, and as such,
the intellectual property is owned by the CRC for Advanced
Computational Systems and the following license applies.  Basically,
C<Config::Access> is free for non-commercial use but if you want to
include it in a commercial product, you must negotiate with the CRC
for Advanced Computational Systems.

  Copyright (c) 1995,1996,1997,1998 ANU and CSIRO on behalf of the
  participants in the CRC for Advanced Computational Systems
  ('ACSys').

  ACSys makes this software and all associated data and documentation
  ('Software') available free of charge for non-commercial purposes
  only.  You may make copies of the Software but you must include all
  of this notice on any copy.

  The Software was developed for research purposes and ACSys does not
  warrant that it is error free or fit for any purpose.  ACSys
  disclaims any liability for all claims, expenses, losses, damages
  and costs any user may incur as a result of using, copying or
  modifying the Software.

=head1 AUTHOR

Tim Potter E<lt>Tim.Potter@anu.edu.auE<gt>

=cut

# any real autoloaded methods go after this line
