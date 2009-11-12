use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::Layer::ICMPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6::Echo;
use Net::Frame::Layer::ICMPv6::NeighborAdvertisement;
use Net::Frame::Layer::ICMPv6::NeighborSolicitation;
use Net::Frame::Layer::ICMPv6::RouterSolicitation;
use Net::Frame::Layer::ICMPv6::RouterAdvertisement;

my $l;

$l = Net::Frame::Layer::ICMPv6->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::ICMPv6::Echo->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::ICMPv6::NeighborAdvertisement->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::ICMPv6::NeighborSolicitation->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::ICMPv6::RouterSolicitation->new;
$l->pack;
$l->unpack;

$l = Net::Frame::Layer::ICMPv6::RouterAdvertisement->new;
$l->pack;
$l->unpack;

ok(1);
