#!/usr/bin/tclsh

set ap [file normalize [file join [file dirname [info script]] ..]]
if { $ap ni $::auto_path } {
  lappend ::auto_path $ap
}
unset ap

proc htob {hex} {
  set val [binary format H* $hex]
  return $val
}

proc runargtest { expected args } {
  set okfail 0
  try {
    {*}$args
    set okfail true
  } on error {err res} {
    set okfail false
  }
  if { $expected eq "ok" && $okfail == false } {
    puts "arg test fail: $args"
  }
  if { $expected eq "fail" && $okfail == true } {
    puts "arg test fail: $args"
  }
}

proc runtest { b } {
  global verbose

  foreach {fn} [list SHA${b}ShortMsg.rsp SHA${b}LongMsg.rsp] {
    puts "=== $fn"
    set fh [open $fn r]
    set have 0
    set count 0
    set fail 0
    set ok 0
    while { [gets $fh line] >= 0 } {
      if { [regexp {^Len = (\d+)} $line all len] } {
        incr have
      }
      if { [regexp {^Msg = (\w+)} $line all tmsg] } {
        incr have
      }
      if { [regexp {^MD = (\w+)} $line all md] } {
        incr have
        if { $have != 3 } {
          set have 0
        }
      }
      if { $have == 3 } {
        set msg [htob $tmsg]
        set tfh [open testsha.bin w]
        fconfigure $tfh -translation binary -encoding binary
        if { $len > 0 } {
          puts -nonewline $tfh $msg
        }
        close $tfh

        if { $verbose } {
          puts -nonewline "  test: $count"
        }
        regsub _ $b / b
        set nmd [sha -bits ${b} -file testsha.bin]
        if { $nmd ne $md } {
          incr fail
          if { $verbose } {
            puts "    file: fail"
          }
        } else {
          incr ok
          if { $verbose } {
            puts "    file: ok"
          }
        }

        incr count

        if { ! $verbose } {
          puts -nonewline [format "\r  %4d %4d %4d " \
              $count $ok $fail]
        }
        set have 0
        file delete -force testsha.bin
      }
    }
    puts ""
    set count 0
    set fail 0
    set ok 0
    close $fh
  }
}

proc main { } {
  global verbose

  set verbose false
  set testb 512
  foreach {arg} $::argv {
    if { $arg eq "-v" } {
      set verbose true
    } elseif { $arg eq "256" } {
      set testb 256
    } elseif { $arg eq "512" } {
      set testb 512
    }
  }

  if { $testb == 256 } {
    package require sha256
    set tlist [list 256 224]
  }
  if { $testb == 512 } {
    package require sha
    set tlist [list 512 384 512_224 512_256]
  }

  # backwards compatibility
  runargtest ok sha $testb -file testsha.tcl ; # old file style
  runargtest ok sha $testb testsha.tcl ; # old data style
  runargtest fail sha $testb testsha.tcl testsha.tcl ; # too many
  runargtest fail sha $testb ; # too few
  runargtest fail sha $testb -file ; # too few
  # current
  runargtest ok sha -bits $testb -file testsha.tcl ; # correct
  runargtest ok sha -bits $testb -data testsha.tcl ; # correct
  runargtest fail sha -bits $testb testsha.tcl ; # no -file/-data
  runargtest fail sha -bits $testb -file ; # too few
  runargtest fail sha -bits $testb -data ; # too few
  runargtest fail sha -bits $testb testsha.tcl ; # too few
  runargtest fail sha -bits $testb -file testsha.tcl testsha.tcl ; # too many

  if { $verbose } {
    puts ""
  }

  if { $testb == 512 } {
    set msg [htob 610061]
    set nmd [sha -bits 512 -data $msg]
    set md 55e7774d4d2c27e0d7ca954e7c89e7b0793a1045b99258ba62326af698fdb69ed538053c2d822b6af706e45a8f1b1fb9d5eeb542c3d0d36c074184c6e65ffb90
    if { $nmd ne $md } {
      puts "data fail: 610061"
    }
    set msg [htob 00]
    set nmd [sha -bits 512 -data $msg]
    set md b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee
    if { $nmd ne $md } {
      puts "data fail: 00"
    }
  }

  foreach {b} $tlist {
    runtest $b
  }
}
::main
