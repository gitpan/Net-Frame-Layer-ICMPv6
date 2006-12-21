use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::Layer::ICMPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6::Echo;
use Net::Frame::Layer::ICMPv6::NeighborAdvertisement;
use Net::Frame::Layer::ICMPv6::NeighborSolicitation;

ok(1);
