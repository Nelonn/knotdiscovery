# knotdiscovery

Library that wraps local service discovery libraries without linking like SDL3

All platforms work out of the box; some offer optional system runtimes for improved stability.

- **Linux**/**FreeBSD**: Bundled mDNS, or optional: `sudo apt-get install avahi-daemon` Dev: `sudo apt install libavahi-common-dev libavahi-client-dev`
- **macOS**: Bonjour
- **Windows**: Bundled mDNS, or via more stable Bonjour: `redist/Bonjour64.msi`
- **Android**: NSD via JNI
- **iOS**: Bonjour
- **ESP32**: ESP mDNS
- **Arduino**: Bundled mDNS

## License

The library is licensed under the [MIT License](https://opensource.org/license/mit/):

Copyright (C) 2026 Michael Neonov <two.nelonn at gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Authors

- **Michael Neonov** ([email](mailto:two.nelonn@gmail.com), [github](https://github.com/Nelonn))
