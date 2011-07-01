package Acme::Indigest::Crypt;
BEGIN {
  $Acme::Indigest::Crypt::VERSION = '0.0010';
}
# ABSTRACT: Acme::Indigest::Crypt

use strict;
use warnings;

use Crypt::Passwd::XS;
use Digest::SHA qw/ sha512_hex /;

sub digest {
    my $self = shift;
    my $passphrase = shift;
    my $limit = shift || 5000;
    die "--<<>>---+__-_-_---+<>\n" unless $limit =~ m/^\d+$/;
    $limit = 1000 if $limit < 1000;

    my $result = sha512_hex( $passphrase );
    for ( 1 .. $limit ) {
        $result .= sha512_hex( $result );
        if ( $_ == $limit || $_ % 5000 == 0 ) {
            $result = substr $result, -512;
        }
    }

    return Crypt::Passwd::XS::unix_sha512_crypt( $result, '' );
}

1;

__END__
=pod

=head1 NAME

Acme::Indigest::Crypt - Acme::Indigest::Crypt

=head1 VERSION

version 0.0010

=head1 AUTHOR

Robert Krimen <robertkrimen@gmail.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2011 by Robert Krimen.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

