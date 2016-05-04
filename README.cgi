Gatling now has primitive CGI support.

To use it, touch ".proxy" in the root of the virtual host, for example

  $ touch default/.proxy

and then start gatling with -C and a regex by which to detect CGIs:

  # gatling -C '\.cgi'

You can also tell gatling to consider all executable files CGI programs:

  # gatling -C+x

Then, even index.html will be run as CGI if it is executable, allowing
for example a dynamically generated homepage on http://example.com/
without index.html having to do a lame redirect.  In this mode, gatling
will do a primitive check and only run CGIs that have the ELF magic
(i.e. look like an ELF binary) or the Shebang (#!, i.e. look like a
shell/perl/whatever script).
