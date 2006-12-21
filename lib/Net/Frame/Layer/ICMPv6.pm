#
# $Id: ICMPv6.pm,v 1.2 2006/12/21 18:07:40 gomor Exp $
#
package Net::Frame::Layer::ICMPv6;
use strict;
use warnings;

our $VERSION = '1.00';

use Net::Frame::Layer qw(:consts :subs);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NF_ICMPv6_CODE_ZERO
      NF_ICMPv6_TYPE_DESTUNREACH
      NF_ICMPv6_CODE_NOROUTE
      NF_ICMPv6_CODE_ADMINPROHIBITED
      NF_ICMPv6_CODE_NOTASSIGNED
      NF_ICMPv6_CODE_ADDRESSUNREACH
      NF_ICMPv6_CODE_PORTUNREACH
      NF_ICMPv6_TYPE_TOOBIG
      NF_ICMPv6_TYPE_TIMEEXCEED
      NF_ICMPv6_CODE_HOPLIMITEXCEED
      NF_ICMPv6_CODE_FRAGREASSEMBLYEXCEEDED
      NF_ICMPv6_TYPE_PARAMETERPROBLEM
      NF_ICMPv6_CODE_ERRONEOUSHERDERFIELD
      NF_ICMPv6_CODE_UNKNOWNNEXTHEADER
      NF_ICMPv6_CODE_UNKNOWNOPTION
      NF_ICMPv6_TYPE_ECHO_REQUEST
      NF_ICMPv6_TYPE_ECHO_REPLY
      NF_ICMPv6_TYPE_ROUTERSOLICITATION
      NF_ICMPv6_TYPE_ROUTERADVERTISEMENT
      NF_ICMPv6_TYPE_NEIGHBORSOLICITATION
      NF_ICMPv6_TYPE_NEIGHBORADVERTISEMENT
      NF_ICMPv6_OPTION_SOURCELINKLAYERADDRESS
      NF_ICMPv6_FLAG_ROUTER
      NF_ICMPv6_FLAG_SOLICITED
      NF_ICMPv6_FLAG_OVERRIDE
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NF_ICMPv6_CODE_ZERO                    => 0;
use constant NF_ICMPv6_TYPE_DESTUNREACH             => 1;
use constant NF_ICMPv6_CODE_NOROUTE                 => 0;
use constant NF_ICMPv6_CODE_ADMINPROHIBITED         => 1;
use constant NF_ICMPv6_CODE_NOTASSIGNED             => 2;
use constant NF_ICMPv6_CODE_ADDRESSUNREACH          => 3;
use constant NF_ICMPv6_CODE_PORTUNREACH             => 4;
use constant NF_ICMPv6_TYPE_TOOBIG                  => 2;
use constant NF_ICMPv6_TYPE_TIMEEXCEED              => 3;
use constant NF_ICMPv6_CODE_HOPLIMITEXCEED          => 0;
use constant NF_ICMPv6_CODE_FRAGREASSEMBLYEXCEEDED  => 1;
use constant NF_ICMPv6_TYPE_PARAMETERPROBLEM        => 4;
use constant NF_ICMPv6_CODE_ERRONEOUSHERDERFIELD    => 0;
use constant NF_ICMPv6_CODE_UNKNOWNNEXTHEADER       => 1;
use constant NF_ICMPv6_CODE_UNKNOWNOPTION           => 2;
use constant NF_ICMPv6_TYPE_ECHO_REQUEST            => 128;
use constant NF_ICMPv6_TYPE_ECHO_REPLY              => 129;
use constant NF_ICMPv6_TYPE_ROUTERSOLICITATION      => 133;
use constant NF_ICMPv6_TYPE_ROUTERADVERTISEMENT     => 134;
use constant NF_ICMPv6_TYPE_NEIGHBORSOLICITATION    => 135;
use constant NF_ICMPv6_TYPE_NEIGHBORADVERTISEMENT   => 136;

use constant NF_ICMPv6_OPTION_SOURCELINKLAYERADDRESS => 0x01;
use constant NF_ICMPv6_OPTION_TARGETLINKLAYERADDRESS => 0x02;

use constant NF_ICMPv6_FLAG_ROUTER    => 0x01;
use constant NF_ICMPv6_FLAG_SOLICITED => 0x02;
use constant NF_ICMPv6_FLAG_OVERRIDE  => 0x04;

our @AS = qw(
   type
   code
   checksum
   icmpType
);
our @AA = qw(
   options
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray (\@AA);

#no strict 'vars';

require Bit::Vector;
require Net::Frame::Layer::ICMPv6::Option;
require Net::Frame::Layer::ICMPv6::Echo;
require Net::Frame::Layer::ICMPv6::NeighborAdvertisement;
require Net::Frame::Layer::ICMPv6::NeighborSolicitation;

sub new {
   shift->SUPER::new(
      type     => NF_ICMPv6_TYPE_ECHO_REQUEST,
      code     => NF_ICMPv6_CODE_ZERO,
      checksum => 0,
      options  => [],
      @_,
   );
}

# XXX: may be better, by keying on type also
sub getKey        { shift->layer }
sub getKeyReverse { shift->layer }

sub match {
   my $self = shift;
   my ($with) = @_;
   my $sType = $self->type;
   my $wType = $with->type;
   if ($sType eq NF_ICMPv6_TYPE_ECHO_REQUEST
   &&  $wType eq NF_ICMPv6_TYPE_ECHO_REPLY) {
      return 1;
   }
   # XXX: maybe should check option type 1 here
   elsif ($sType eq NF_ICMPv6_TYPE_NEIGHBORSOLICITATION
      &&  $wType eq NF_ICMPv6_TYPE_NEIGHBORSOLICITATION
      &&  $with->icmpType && $with->options) {
      return 1;
   }
   0;
}

sub getOptionsLength {
   my $self = shift;
   my $len = 0;
   $len += $_->getLength for $self->options;
   $len;
}

sub getLength {
   my $self = shift;
   my $len = 4;
   if ($self->icmpType) {
      $len += $self->icmpType->getLength;
   }
   $len += $self->getOptionsLength;
   $len;
}

sub pack {
   my $self = shift;

   my $raw = $self->SUPER::pack('CCn',
      $self->type, $self->code, $self->checksum,
   ) or return undef;

   if ($self->icmpType) {
      $raw .= $self->icmpType->pack
         or return undef;

      # Move payload from ICMP type to $self
      $self->payload($self->icmpType->payload);
      $self->icmpType->payload(undef);
   }

   for ($self->options) {
      $raw .= $_->pack;
   }

   $self->raw($raw);
}

sub unpack {
   my $self = shift;

   my ($type, $code, $checksum, $payload) =
      $self->SUPER::unpack('CCn a*', $self->raw)
         or return undef;

   $self->type($type);
   $self->code($code);
   $self->checksum($checksum);

   if ($payload) {
      if ($type eq NF_ICMPv6_TYPE_ECHO_REQUEST
      ||  $type eq NF_ICMPv6_TYPE_ECHO_REPLY) {
         $self->icmpType(
            Net::Frame::Layer::ICMPv6::Echo->new(raw => $payload)->unpack,
         );
      }
      elsif ($type eq NF_ICMPv6_TYPE_NEIGHBORSOLICITATION) {
         my $icmp = Net::Frame::Layer::ICMPv6::NeighborSolicitation->new(
            raw => $payload,
         )->unpack;
         $self->_unpackOptions($icmp, $icmp->payload) if $icmp->payload;
         $self->icmpType($icmp);
      }
      elsif ($type eq NF_ICMPv6_TYPE_NEIGHBORADVERTISEMENT) {
         my $icmp = Net::Frame::Layer::ICMPv6::NeighborAdvertisement->new(
            raw => $payload,
         )->unpack;
         $self->_unpackOptions($icmp, $icmp->payload) if $icmp->payload;
         $self->icmpType($icmp);
      }

      if ($self->icmpType && $self->icmpType->payload) {
         $self->payload($self->icmpType->payload);
         $self->icmpType->payload(undef);
      }
   }

   $self;
}

sub _unpackOptions {
   my $self = shift;
   my ($icmp, $payload) = @_;

   my @options = ();
   while ($payload) {
      my $opt = Net::Frame::Layer::ICMPv6::Option->new(raw => $payload)->unpack;
      push @options, $opt;
      $payload = $opt->payload;
   }

   $icmp->payload(undef);
   $self->payload(undef);
   $self->options(\@options);
}

sub computeChecksums {
   my $self = shift;
   my ($h)  = @_;

   my $zero       = Bit::Vector->new_Dec(24, 0);
   my $nextHeader = Bit::Vector->new_Dec( 8, $h->{nextHeader});
   my $v32        = $zero->Concat_List($nextHeader);

   my $packed = $self->SUPER::pack('a*a*NNCCna*',
      inet6Aton($h->{src}), inet6Aton($h->{dst}), $h->{payloadLength},
      $v32->to_Dec, $self->type, $self->code, 0, $self->icmpType->pack,
   ) or return undef;

   $self->checksum(inetChecksum($packed));

   1;
}

sub encapsulate {
   my $self = shift;

   return $self->nextLayer if $self->nextLayer;

#  if ($self->payload) {
#     my $type = $self->type;
#     #if ($type eq NF_ICMPv6_TYPE_DESTUNREACH
#     #||  $type eq NF_ICMPv6_TYPE_REDIRECT
#     #||  $type eq NF_ICMPv6_TYPE_TIMEEXCEED) {
#        #return 'IPv6';
#     #}
#  }

   NF_LAYER_NONE;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf "$l: type:%d  code:%d  checksum:0x%04x",
      $self->type, $self->code, $self->checksum;

   if ($self->icmpType) {
      $buf .= "\n".$self->icmpType->print;
   }

   for ($self->options) {
      $buf .= "\n".$_->print;
   }

   $buf;
}

1;

__END__

=head1 NAME

Net::Frame::Layer::ICMPv6 - Internet Control Message Protocol v6 layer object

=head1 SYNOPSIS

   use Net::Frame::Layer::ICMPv6 qw(:consts);

   my $icmp = Net::Frame::Layer::ICMPv6->new(
      type     => NF_ICMPv6_TYPE_ECHO_REQUEST,
      code     => NF_ICMPv6_CODE_ZERO,
      checksum => 0,
      options  => [],
   );

   # Build an ICMPv6 echo-request
   use Net::Frame::Layer::ICMPv6::Echo;
   my $echo = Net::Frame::Layer::ICMPv6::Echo->new(payload => 'echo');
   $icmp->icmpType($echo);
   $icmp->pack;

   print $icmp->print."\n";

   # Build an ICMPv6 neighbor-solicitation
   use Net::Frame::Layer::ICMPv6::NeighborSolicitation;
   my $solicit = Net::Frame::Layer::ICMPv6::NeighborSolicitation->new(
      targetAddress => $targetIpv6Address,
   );
   $icmp->type(NF_ICMPv6_TYPE_NEIGHBORSOLICITATION);
   $icmp->icmpType($solicit);
   $icmp->pack;

   print $icmp->print."\n";

   # Read a raw layer
   my $layer = Net::Frame::Layer::ICMPv6->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv6 layer.

RFC: http://www.rfc-editor.org/rfc/rfc2463.txt
RFC: http://www.rfc-editor.org/rfc/rfc2461.txt
RFC: http://www.rfc-editor.org/rfc/rfc2460.txt

See also B<Net::Frame::Layer> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

=item B<code>

Type and code fields. See B<CONSTANTS>.

=item B<checksum>

The checksum of ICMPv6 header.

=item B<icmpType>

A pointer to a B<Net::Frame::Layer::ICMPv6::*> layer.

=item B<options>

An arrayref of B<Net::Frame::Layer::Option> objects.

=back

The following are inherited attributes. See B<Net::Frame::Layer> for more information.

=over 4

=item B<raw>

=item B<payload>

=item B<nextLayer>

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<computeChecksums>

Computes the ICMPv6 checksum.

=item B<getOptionsLength>

Returns the length in bytes of options, 0 if none.

=item B<getKey>

=item B<getKeyReverse>

These two methods are basically used to increase the speed when using B<recv> method from B<Net::Frame::Simple>. Usually, you write them when you need to write B<match> method.

=item B<match> (Net::Frame::Layer::ICMPv6 object)

This method is mostly used internally. You pass a B<Net::Frame::Layer::ICMPv6> layer as a parameter, and it returns true if this is a response corresponding for the request, or returns false if not.

=back

The following are inherited methods. Some of them may be overriden in this layer, and some others may not be meaningful in this layer. See B<Net::Frame::Layer> for more information.

=over 4

=item B<layer>

=item B<computeLengths>

=item B<computeChecksums>

=item B<pack>

=item B<unpack>

=item B<encapsulate>

=item B<getLength>

=item B<getPayloadLength>

=item B<print>

=item B<dump>

=back

=head1 CONSTANTS

Load them: use Net::Frame::Layer::ICMPv6 qw(:consts);

=over 4

=item B<NF_ICMPv6_CODE_ZERO>

=item B<NF_ICMPv6_TYPE_DESTUNREACH>

=item B<NF_ICMPv6_CODE_NOROUTE>

=item B<NF_ICMPv6_CODE_ADMINPROHIBITED>

=item B<NF_ICMPv6_CODE_NOTASSIGNED>

=item B<NF_ICMPv6_CODE_ADDRESSUNREACH>

=item B<NF_ICMPv6_CODE_PORTUNREACH>

=item B<NF_ICMPv6_TYPE_TOOBIG>

=item B<NF_ICMPv6_TYPE_TIMEEXCEED>

=item B<NF_ICMPv6_CODE_HOPLIMITEXCEED>

=item B<NF_ICMPv6_CODE_FRAGREASSEMBLYEXCEEDED>

=item B<NF_ICMPv6_TYPE_PARAMETERPROBLEM>

=item B<NF_ICMPv6_CODE_ERRONEOUSHERDERFIELD>

=item B<NF_ICMPv6_CODE_UNKNOWNNEXTHEADER>

=item B<NF_ICMPv6_CODE_UNKNOWNOPTION>

=item B<NF_ICMPv6_TYPE_ECHO_REQUEST>

=item B<NF_ICMPv6_TYPE_ECHO_REPLY>

=item B<NF_ICMPv6_TYPE_ROUTERSOLICITATION>

=item B<NF_ICMPv6_TYPE_ROUTERADVERTISEMENT>

=item B<NF_ICMPv6_TYPE_NEIGHBORSOLICITATION>

=item B<NF_ICMPv6_TYPE_NEIGHBORADVERTISEMENT>

=item B<NF_ICMPv6_OPTION_SOURCELINKLAYERADDRESS>

Various types and codes for ICMPv6 header.

=item B<NF_ICMPv6_FLAG_ROUTER>

=item B<NF_ICMPv6_FLAG_SOLICITED>

=item B<NF_ICMPv6_FLAG_OVERRIDE>

Various flags for some ICMPv6 messages.

=back

=head1 SEE ALSO

L<Net::Frame::Layer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
