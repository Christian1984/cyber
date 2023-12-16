# Web Requests

this note covers contents from the Hack The Box Academy Module "Web Requests" (https://academy.hackthebox.com/module/35)

## HTTP

a _Fully Qualified Domain Name (FQDN)_ is used as a _Uniform Resource Locator (URL)_ to reach the desired website, like www.hackthebox.com.

![URL components](<images/010 - Web Requests/url-components.png>)

## HTTP Flow

![HTTP Flow](<images/010 - Web Requests/http-flow.png>)

## cURL

use `curl` (client URL) to submit http requests via the command line.

- `curl -L <url>` allows cURL to follow 301 redirects. the `-k` flag disables the certificate check and warning when using https.
- the `-v` option enables verbose output, while `-vvv` enables very verbose output.
- `-o` will send the output to the specified file. use `-o -` if a warning occurs and you want to force output to console.
- the `-I` flag can be used to only send and receive headers.
- `-i` prints both the header and the body
- `-X` can be used to specify the http-Method

pipe responses into `jq` to pretty print jason responses, i.e. `curl http://example.com/api/city/london | jq`
