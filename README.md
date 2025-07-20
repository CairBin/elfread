# elfread

## Description

A tool under Rust to parse ELF32/64 files.

## Usage

Output elf header information:

```sh
elfread [FILE]
```

for example:
```sh
elfread rv64.elf
```

Output section header information:
```sh
elfread [FILE] -s
```

Output program header information:
```sh
elfread [FILE] -p
```

## Todo

* Support more machines
* Parse symbol table
* Improve command parameters and output styles
* Support C interface