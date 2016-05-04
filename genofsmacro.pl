#!/usr/bin/perl
$max=80;

# print "#define OFS32(buf,x) \\\n";
# for ($i=0; $i<$max; ++$i) {
#   print "  ((buf[$i]==x[0] && buf[$i+1]==x[1] && buf[$i+2]==x[2] && buf[$i+3]==x[3])?$i: \\\n";
# }
# print "  -1",")" x $max,"\n\n";

print "#define OFS16(buf,x) \\\n";
for ($i=0; $i<$max; ++$i) {
  print "  ((sizeof(buf)>$i+1 && buf[$i]==x[0] && buf[$i+1]==x[1])?$i: \\\n";
}
print "  -1",")" x $max,"\n\n";


