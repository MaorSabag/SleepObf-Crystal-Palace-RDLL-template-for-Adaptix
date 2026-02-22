x64:
	load "../../build/loader.x64.o"        # read the loader COFF
		make pic +gofirst +optimize +mutate +disco     		# turn it into PIC and ensure the go function is at the start

	run "../../crystal_palace/specs/services.spec"  # run the services spec to merge the services PIC and resolve functions

	run "../../crystal_palace/specs/pico.spec"  # run the pico spec to export the setup_hooks function and finalize the PIC
		link "pico"

	generate $KEY 128  # generate a random 128-byte key and assign it to the $KEY variable

	push $DLL
		xor $KEY    # xor the dll with the key
		preplen     # prepend its length
		link "dll"  # link it to the "dll" section

	push $KEY
		preplen      # prepend the key's length
		link "mask"  # link it to the "mask" section

	
	export  # export the final pic