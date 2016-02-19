# POWER9 config file
# run with:
#  export SKIBOOT=~/src/skiboot-p9/skiboot.lid
#  export SKIBOOT_INITRD=~/initramfs-le.cpio.gz
#  export SKIBOOT_ZIMAGE=~/src/linux-p9/vmlinux
#  export SKIBOOT_SIMCONF=~/src/skiboot-p9/external/mambo/p9.tcl
#  export SKIBOOT_AUTORUN=1
#  ~/src/mambo/run/p9/run_cmdline -f ~/src/skiboot-p9/external/mambo/skiboot.tcl
#

if { [file exists $env(LIB_DIR)/ppc/step.tcl] } then {
    source $env(LIB_DIR)/common/mambo_init.tcl
    source $env(LIB_DIR)/ppc/step.tcl
}

# Hook run at conf time
proc sim_conf { } {
    global default_config

    if { $default_config == "P9" } {
	puts "Configuring for POWER9!"

	# make sure we look like a POWER9
	myconf config processor/initial/SIM_CTRL1 0xc228000000000000
    }

# Don't use these!
# Old PTE format:
#    myconf config processor/initial/SIM_CTRL1 0x4210000000000000
# New PTE format:
#    myconf config processor/initial/SIM_CTRL1 0x4218000000000000
# New PTE format with partition table
#    myconf config processor/initial/SIM_CTRL1 0x4208000000000000
}

# Hook run when mysim is present
proc sim_sim { } {
    global mconf
    global default_config

    # example cmdline option
    of::set_bootargs "rw root=/dev/mambobd0 console=hvc0 init=/bin/bash"

    if { $default_config == "P9" } {
	puts "Sim for POWER9!"

	# Tell ibm,pa-features that we support radix (byte 40 bit 0)
	set pir 0
	for { set c 0 } { $c < $mconf(cpus) } { incr c } {
	    set cpu_node [mysim of find_device "/cpus/PowerPC@$pir"]
	    # POWER9 PAPR defines upto bytes 62-63
	    set reg [list 0x4000f63fc70080c0 \
			      0x8000000000000000 \
			      0x0000800080008000 \
			      0x8000800080008000 \
			      0x80008000C0008000 \
			      0x8000800080008000 \
			      0x8000800080008000 \
			      0x8000800080008000 \
			      0x8000000000000000 ]
	    mysim of addprop $cpu_node array64 "ibm,pa-features" reg

	    set pir [expr $pir + $mconf(threads) ]
	}
    }

}

# Hook run with running simulation
proc sim_run { } {
    puts "run!!!!!"
}

