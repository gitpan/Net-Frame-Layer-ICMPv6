#
# $Id: NeighborAdvertisement.pm,v 1.2 2006/12/21 22:33:56 gomor Exp $
#
package Net::Frame::Layer::ICMPv6::NeighborAdvertisement;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts :subs);
our @ISA = qw(Net::Frame::Layer);

our @AS = qw(
   flags
   reserved
   targetAddress
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

#no strict 'vars';

use Net::Frame::Layer::ICMPv6 qw(:consts);
require Bit::Vector;

sub new {
   shift->SUPER::new(
      flags         => NF_ICMPv6_FLAG_SOLICITED,
      reserved      => 0,
      targetAddress => '::1',
      @_,
   );
}

sub getLength { 20 }

sub pack {
   my $self = shift;

   my $flags    = Bit::Vector->new_Dec( 3, $self->flags);
   my $reserved = Bit::Vector->new_Dec(29, $self->reserved);
   my $v32      = $flags->Concat_List($reserved);

   $self->raw($self->SUPER::pack('Na16',
      $v32->to_Dec, inet6Aton($self->targetAddress),
   )) or return undef;

   $self->raw;
}

sub unpack {
   my $self = shift;

   my ($flagsReserved, $targetAddress, $payload) =
      $self->SUPER::unpack('Na16 a*', $self->raw)
         or return undef;

   my $v32 = Bit::Vector->new_Dec(32, $flagsReserved);

   $self->reserved($v32->Chunk_Read(29,  0));
   $self->flags   ($v32->Chunk_Read( 3, 29));
   $self->targetAddress(inet6Ntoa($targetAddress));

   $self->payload($payload);

   $self;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: flags:%02x  reserved:%d\n".
           "$l: targetAddress:%s",
              $self->flags, $self->reserved, $self->targetAddress;
}

1;

__END__

=head1 NAME

Net::Frame::Layer::ICMPv6::NeighborAdvertisement - ICMPv6 Neighbor Advertisement type object

=head1 SYNOPSIS

   use Net::Frame::Layer::ICMPv6::NeighborAdvertisement;

   my $layer = Net::Frame::Layer::ICMPv6::NeighborAdvertisement->new(
      flags         => NF_ICMPv6_FLAG_SOLICITED,
      reserved      => 0,
      targetAddress => '::1',
   );
   $layer->pack;

   print 'RAW: '.$layer->dump."\n";

   # Read a raw layer
   my $layer = Net::Frame::Layer::ICMPv6::NeighborAdvertisement->new(
      raw => $raw,
   );

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ICMPv6 Neighbor Advertisement object.

See also B<Net::Frame::Layer> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<flags>

ICMPv6 Neighbor Advertisement flags. See B<CONSTANTS>.

=item B<reserved>

Should be zeroed.

=item B<targetAddress>

The IPv6 address you want to lookup (for example).

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

No constants here.

=head1 SEE ALSO

L<Net::Frame::Layer::ICMPv6>, L<Net::Frame::Layer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
