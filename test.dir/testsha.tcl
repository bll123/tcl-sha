#!/usr/bin/tclsh

proc htob {hex} {
  set val [binary format H* $hex]
  return $val
}

proc runargtest { expected args } {
  global verbose

  if { $verbose } {
    puts "runargtest: $expected $args"
  }
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
    regsub / $fn _ fn
    puts "=== $fn"
    set fh [open $fn r]
    set have 0
    set count 0
    set fail 0
    set ok 0
    while { [gets $fh line] >= 0 } {
      if { [regexp {^exit$} $line all len] } {
        exit
      }
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
          puts "-- test: $count"
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
          puts -nonewline [format "\r  %4d ok:%4d fail:%4d " \
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

  foreach {fn} [list HMAC.rsp] {
    set fh [open $fn r]
    set have 0
    set count 0
    set fail 0
    set ok 0
    set havelen 0
    while { [gets $fh line] >= 0 } {
      if { [regexp {^exit$} $line all len] } {
        exit
      }
      if { [regexp {^\[L=(\d+)\]$} $line all len] } {
        set havelen 0
        set have 0
        if { $len == 28 && $b eq "224" } {
          incr havelen
        }
        if { $len == 32 && $b eq "256" } {
          incr havelen
        }
        if { $len == 48 && $b eq "384" } {
          incr havelen
        }
        if { $len == 64 && $b eq "512" } {
          incr havelen
        }
        if { $havelen } {
          puts "=== $b $fn"
        }
      }
      if { [regexp {^Tlen = (\w+)} $line all testlen] } {
        incr have
        set testlen [expr {$testlen * 2}]
      }
      if { [regexp {^Key = (\w+)} $line all tkey] } {
        incr have
      }
      if { [regexp {^Msg = (\w+)} $line all tmsg] } {
        incr have
      }
      if { [regexp {^Mac = (\w+)} $line all mac] } {
        incr have
        if { $have != 4 } {
          set have 0
        }
      }
      if { $havelen == 1 && $have == 4 } {
        set key [htob $tkey]

        set tfh [open testkey.bin w]
        fconfigure $tfh -translation binary -encoding binary
        if { $len > 0 } {
          puts -nonewline $tfh $key
        }
        close $tfh

        set msg [htob $tmsg]

        set tfh [open testsha.bin w]
        fconfigure $tfh -translation binary -encoding binary
        if { $len > 0 } {
          puts -nonewline $tfh $msg
        }
        close $tfh

        if { $verbose } {
          puts "-- test: $count"
        }
        regsub _ $b / b
        try {
          set nmac [sha -bits ${b} -keyfile testkey.bin -mac hmac -file testsha.bin]
        } on error {err res} {
          puts ""
          puts "res: $res"
          set nmac {}
        }
        if { [string compare -length $testlen $nmac $mac] != 0 } {
          incr fail
          if { $verbose } {
            puts "    testlen: $testlen"
            puts "    got: $nmac"
            puts "    exp: $mac"
            puts "    file: fail"
          }
        } else {
          incr ok
          if { $verbose } {
            puts "    testlen: $testlen"
            puts "    got: $nmac"
            puts "    exp: $mac"
            puts "    file: ok"
          }
        }

        incr count

        if { ! $verbose } {
          puts -nonewline [format "\r  %4d ok:%4d fail:%4d " \
              $count $ok $fail]
        }
        set have 0
        file delete -force testsha.bin
        file delete -force testkey.bin
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
    load [file join .. sha256[info sharedlibextension]]
    set tlist [list 256 224]
  }
  if { $testb == 512 } {
    load [file join .. sha[info sharedlibextension]]
    set tlist [list 512 384 512/224 512/256]
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
  runargtest fail sha -bits $testb testsha.tcl ; # incorrect usage, too few
  runargtest fail sha -bits $testb -file testsha.tcl testsha.tcl ; # too many

  if { $verbose } {
    puts ""
  }

  foreach {b} $tlist {
    runtest $b
  }
}
::main
