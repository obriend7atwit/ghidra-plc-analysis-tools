# Troubleshooting

## Script missing from Script Manager

Confirm the file is in a configured script directory, the filename matches the public class, and Script Manager was refreshed.

## Raw binary produces nonsense

Recheck processor, endianness, bitness, ARM/Thumb mode, and image base.

## No functions are created

The file may be data, compressed, encrypted, unsupported bytecode, imported with the wrong language, or using unusual function conventions.

## Decompiler output looks wrong

Check the function boundary, calling convention, indirect calls, stack-based frames, and relocations. Compare against assembly.
