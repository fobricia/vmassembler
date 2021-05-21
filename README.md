<div align="center">
    <div>
        <img src="https://githacks.org/uploads/-/system/project/avatar/374/icon-5.png"/>
    </div>
</div>

# vmassembler - VMProtect 2 Virtual Instruction Assembler

vmassembler is a small C++ project which uses [flex](https://en.wikipedia.org/wiki/Flex_(lexical_analyser_generator)) and [bison](https://www.gnu.org/software/bison/manual/) to parse `.vasm` files and assemble virtual instructions. The project inherits [vmprofiler](https://githacks.org/vmp2/vmprofiler) which is used to identify vm handler's, provide them with a name, immidate value size, and other meta data to aid in assembling virtual instructions.

### Contents 

The repo contains the following notable folders and files:

* `dependencies/` - vmprofiler is the only dependency for this project...
* `src/` - source code for the vmassembler...
    * `compiler.cpp` - responsible for encoding and encrypting virtual instructions...
    * `parser.cpp` - a singleton class which is used in `parser.y`...
    * `parser.y` - bison rules for parsing tokens. This contains only a handful of rules...
    * `lexer.l` - lex rules for the vmassembler...

### Usage Requirements

In order to use the virtual instruction assembler you must first have a few values at hand. The required values are listed below:

* `vm_entry rva` - relative virtual address to a vm_entry...
* `image base` - image base value from optional headers...
* a path to a vasm file is required...
* `advancement` - which way the virtual instruction pointer advances... 
* `out path` - a path to where the vmasm file will be stored...