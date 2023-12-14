# web applications

## obfuscation

js scripts are often minified and obfuscated. either to protect the code from being inspected, copied, and tampered with or (by attackers) to bypass filters.

- https://obfuscator.io/ - web app to obfuscate js code
- https://jsconsole.com/ - a simple console to execute js code

## deobfuscation

code can be beatified directly in the browser's dev tools (Debugger -> (script) -> { } (below the "editor" window))

- https://prettier.io/playground/ - beatifier
- https://beautifier.io/ - another beatifier
- https://matthewfl.com/unPacker.html - web app to deobfuscate jso

## encodings

raw strings can be encoded in multiple ways, such as

- Base64, e.g. aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K
- Hex, e.g. 68747470733a2f2f7777772e6861636b746865626f782e65752f0a
- Caesar/Rot 13, e.g. uggcf://jjj.unpxgurobk.rh/

They are all relatively easy to spot and decode:

### base64

base64 encoded strings are easily spotted since they only contain alpha-numeric characters. however, the most distinctive feature of base64 is its padding using = characters. the length of base64 encoded strings has to be in a multiple of 4. if the resulting output is only 3 characters long, for example, an extra = is added as padding, and so on.

- encode: e.g. `echo -n hello world | base64`
- decode: e.g. `curl 94.237.53.82:44561/serial.php -X POST -s | base64 -d`

### hex

any string encoded in hex would be comprised of hex characters only, which are 16 characters only: 0-9 and a-f. that makes spotting hex encoded strings just as easy as spotting base64 encoded strings.

- encode: e.g. `echo -n hello world | xxd -p`
- decode: e.g. `curl 94.237.53.82:44561/serial.php -X POST -s | xxd -p -r`

> the `p` flag makes it a plain dump, without any kind of formatting

### caesar/rot13

even though this encoding method makes any text looks random, it is still possible to spot it because each character is mapped to a specific character. for example, in rot13, http://www becomes uggc://jjj, which still holds some resemblances and may be recognized as such.

there isn't a specific command in linux to do rot13 encoding. however, it is fairly easy to create our own command to do the character shifting:

- encode: e.g. `echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
- decode: e.g. `echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

alternatively, use a web app like https://rot13.com/

### other types of encoding

there are hundreds of other encoding methods we can find online. even though these are the most common, sometimes we will come across other encoding methods, which may require some experience to identify and decode.

if you face any similar types of encoding, first try to determine the type of encoding, and then look for online tools to decode it.

https://www.boxentriq.com/code-breaking/cipher-identifier can help with identifying encodings.
