#
# $Id: Makefile.PL,v 1.1 2006/12/21 17:54:59 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame::Layer::ICMPv6',
   VERSION_FROM  => 'lib/Net/Frame/Layer/ICMPv6.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame/Layer/ICMPv6.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Net::Frame => 0,
   },
);
