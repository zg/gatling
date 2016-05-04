#!/usr/bin/perl
while (<>) {
  chomp;
  my @x=split(" ");
  if ($x[0] =~ m/^\d{4}-\d\d-\d\d$/) {
    my $tmp = "$x[0]|$x[1]";
    shift @x;
    $x[0]=$tmp;
  }
  if ($x[1] =~ /^(GET|POST|HEAD)/) {
    if ($x[1] =~ /SSL/) {
      $x[3] = "https://" . $x[7] . $x[3];
    } else {
      $x[3] = "http://" . $x[7] . $x[3];
    }
  }
  if ($x[1] eq "accept") {
    $ip{$x[2]} = $x[3];
  } elsif ($#x == 7) {
    $x[2] = $ip{$x[2]};
    $x[2] = "0.0.0.0" if ($x[2] eq "");
    next if ($x[2] eq "82.146.42.231");
    print join(" ",@x),"\n";
  }
}
