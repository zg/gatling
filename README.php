gatling now supports SCGI and FastCGI and can thus be used to run, for
example, PHP scripts.

Here's how to use it.

  1. compile gatling with proxy mode (this is on by default).
  2. enable proxying for the virtual host you want to use:

       $ touch www.example.com:80/.proxy

  3. run php in FastCGI mode (adjust path to PHP as needed):

       $ PHP_FCGI_CHILDREN=16 /opt/php/bin/php-cgi -b 127.0.0.1:8001

  4. tell gatling to use this to run the PHP scripts:

       # gatling -O 'F/127.0.0.1/8001/\.php'

  5. now, you should be able to browse to

     http://www.example.com/t.php

Note that the physical t.php file must exist in your http root.  gatling
checks if it's there and tells php to parse it from there.  This file
needs to be there but it does not need to be world readable.  Gatling
will only serve files that are world readable.  It is thus a good idea
to make the php files only readable to the user or group php runs under,
and not to the world.  That way you cannot accidentally serve them via
gatling.  The same trick goes for include files or other files that the
php scripts may want to read but that do not need to be served by
gatling directly.
