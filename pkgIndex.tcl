set shaver 2.1.1
set osplatform $::tcl_platform(platform)
set osname [string tolower $::tcl_platform(os)]
set osbits 64
# this is not valid for windows.
# windows correctly sets itself below.
if { $::tcl_platform(wordSize) == 4 } {
  set osbits 32
}
if { $osplatform eq "windows" } {
  set osname windows
  set osbits 32
  set k {ProgramFiles(x86)}
  if { [info exists ::env($k)] } {
    set osbits 64
  }
}

package ifneeded sha ${shaver} \
    [list load [file join $dir ${osname}${osbits} \
    sha[info sharedlibextension]]]

unset -nocomplain osbits
unset -nocomplain osplatform
unset -nocomplain osname
unset -nocomplain shaver
