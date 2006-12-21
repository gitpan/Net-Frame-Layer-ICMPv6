#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Layer qw(:subs);

my $dev    = shift || die("Specify network interface\n");
my $target = shift || die("Specify target IPv6 address\n");

if ($target) {
   $target = getHostIpv6Addr($target) || die("Unable to revolv hostname\n");
}

use Net::Frame::Device;
use Net::Frame::Simple;
use Net::Frame::Layer::ETH qw(:consts);
use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6::NeighborSolicitation;

my $oDevice = Net::Frame::Device->new(dev => $dev);

use Net::Frame::Dump::Online;
my $oDump = Net::Frame::Dump::Online->new(
   dev           => $oDevice->dev,
   filter        => 'ip6',
   timeoutOnNext => 5,
);
$oDump->start;

my $eth = Net::Frame::Layer::ETH->new(
   src  => $oDevice->mac,
   type => NF_ETH_TYPE_IPv6,
);

my $ip = Net::Frame::Layer::IPv6->new(
   src        => $oDevice->ip6,
   dst        => $target,
   nextHeader => NF_IPv6_PROTOCOL_ICMPv6,
);

my $icmp = Net::Frame::Layer::ICMPv6->new(
   type     => NF_ICMPv6_TYPE_NEIGHBORSOLICITATION,
   icmpType => Net::Frame::Layer::ICMPv6::NeighborSolicitation->new(
      targetAddress => $target,
   ),
);

my $oSimple = Net::Frame::Simple->new(
   layers => [ $eth, $ip, $icmp, ],
);
print $oSimple->print."\n";

use Net::Write::Layer2;

my $oWrite = Net::Write::Layer2->new(dev => $oDevice->dev);
$oWrite->open;
$oWrite->send($oSimple->raw);
$oWrite->close;

my $reply;
for (1..3) {
   print 'Try number: '.$_."\n";
   until ($oDump->timeout) {
      if ($reply = $oSimple->recv($oDump)) {
         last;
      }
   }
   last if $reply;
   $oDump->timeoutReset;
}

if ($reply) {
   print 'RECV:'."\n".$reply->print."\n" if $reply;
   for ($reply->ref->{ICMPv6}->options) {
      if ($_->type eq NF_ICMPv6_OPTION_SOURCELINKLAYERADDRESS) {
         my $mac = unpack('H*', $_->value);
         print convertMac($mac)."\n";
      }
   }
}

END { $oDump && $oDump->isRunning && $oDump->stop }
