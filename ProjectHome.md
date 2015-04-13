This project will host diverse scripts that I create and use when I reverse engineer code. The scripts will generally be Python or IDAPython and mostly focused on performing specific and small tasks.

Some of the scripts will need different libraries/modules such as:
  * [pefile](http://code.google.com/p/pefile/)
  * [idapython](http://code.google.com/p/idapython/)


## Scripts ##

### IDA file Patcher ###

This simple script will scan the current IDB for changes and generate a patched file

If the original input file can't be found at the original location where the IDB was generated from, it will prompt the user with a dialog to choose the original file. The original file is needed in order to compare the modifed data and prepare a patched file.

The script will then scan the IDB for values that differ from the original ones. Data can be patched in the IDB through IDC/IDAPython function such as:

> `PatchByte()` / `PatchWord()` / `PatchDword()`

Once the changes have been collected the script will propmt for a new file where to store the patched data.

This script works with generic data files, PE files, ELF, raw data, etc As long as the modified data has a counterpart on the file, it will be patched.
Beware that if the user adds new segments those will have no counterpart in the original file and the script will ignore data in those.

[Link to the latest revision](http://code.google.com/p/reverse-engineering-scripts/source/browse/trunk/ida_file_patch.py)

### IDA PEiD ###

This small script is intended as a small aid at finding possible packer code in an IDA database. It will run PEiD signatures at all locations defined as entry points.

The script requires [pefile](http://code.google.com/p/pefile/)

The PEiD signatures will be automatically fetched from google-code. They can be found in the [downloads section](http://code.google.com/p/reverse-engineering-scripts/downloads/list).
The signatures used are those created by BoB / Team PEiD (used with permission)

[Link to the latest revision](http://code.google.com/p/reverse-engineering-scripts/source/browse/trunk/ida_peid.py)