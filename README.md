# Hyperion Dumper

HyperionDumper is a dumper specifically targetting the Roblox Hyperion module, it dumps it from memory and resolves statically what we call 'opaque predicates' those are basically branches of code that will be always taken.

Hyperion uses this to confuse reverse engineering tools and make statically reversing much harder, however with most (if not all) opaque predicates resolves, you will have much easier time reversing hyperion.

While Hyperion contains many more static obfuscations (like lazy importer, syscall number obfuscation, dead store), opaque predicates are mostly the reason why reverse engineering tools like IDA or Binary Ninja refuse to properly analyze functions.

In the future, I might consider adding resolving another obfuscation features of hyperion, but I'm not sure about that.

### Usage

To use this tool, simply download a release from [here](https://github.com/Pixeluted/HyperionDumper/releases/latest), then run it while roblox is open and once the dumper is done, it will write a 'dump.bin' file to the same directory the executable was placed within, and you can happily go reversing.

### Building

If you want to build this project yourself, you will need to simply git clone it and then run
```
git submodule update --init --recursive
```

For CLion users (CMake users) this should be matter of just opening it and building it.

However, for visual studio users I have bad news because I have no idea how to build it there, so good luck figuring it out.
