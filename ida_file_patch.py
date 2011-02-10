# -*- coding: Latin-1 -*-
"""IDA file patching script

This simple script will scan the current IDB for changes and generate a
patched file

If the original input file can't be found at the original location where the
IDB was generated from, it will prompt the user with a dialog to choose the
original file. The original file is needed in order to compare the modifed
data and prepare a patched file.

The script will then scan the IDB for values that differ from the original
ones. Data can be patched in the IDB through IDC/IDAPython function such as:

  PatchByte()/PatchWord()/PatchDword()

Once the changes have been collected the script will propmt for a new file
where to store the patched data

This script works with generic data files, PE files, ELF, raw data, etc
As long as the modified data has a counterpart on the file, it will be patched
Beware that if the user adds new segments those will have no counterpart in
the original file and the script will ignore data in those.

Copyright (c) 2011 Ero Carrera <ero.carrera@gmail.com>

All rights reserved.
"""

__revision__ = "$LastChangedRevision$"
__author__ = 'Ero Carrera'
__version__ = '0.%d' % int( __revision__[21:-2] )
__contact__ = 'ero.carrera@gmail.com'


import os
import idaapi


def find_changed_bytes():

    changed_bytes = list()

    for seg_start in Segments():
        for ea in range(seg_start, SegEnd(seg_start) ):
            if isLoaded(ea):
                byte = Byte(ea)
                original_byte = GetOriginalByte(ea)
                if byte != original_byte:
                    changed_bytes.append( (ea, byte, original_byte) )
            
    return changed_bytes



def patch_file(data, changed_bytes):
    
    for ea, byte, original_byte in changed_bytes:
        print '%08x: %02x original(%02x)' % (ea, byte, original_byte)
                
        file_offset = idaapi.get_fileregion_offset( ea )
        
        original_char = chr( original_byte )
        char = chr( byte )
        
        if data[ file_offset ] == original_char:
            data[ file_offset ] = char
    
    patched_file = idc.AskFile( 1, '*.*', 'Choose new file')
    if patched_file:
        with file(patched_file, 'wb') as f:
            f.write( ''.join( data ) )



def main():
    
    print 'Finding changed bytes...',
    changed_bytes = find_changed_bytes()
    print 'done. %d changed bytes found' % len(changed_bytes)
    
    if changed_bytes:
        original_file = GetInputFilePath()
        print original_file
    
        if not os.path.exists(original_file):
            original_file = idc.AskFile( 0, '*.*', 'Select original file to patch')
        
        if os.path.exists(original_file):

            with file(original_file, 'rb') as f:
                data = list( f.read() )

            patch_file(data, changed_bytes)
        
        else:
            print 'No valid file to patch provided'

    else:
        print 'No changes to patch'

        
print '---- Running script ----'
main()
print '---- Script finished ----'
