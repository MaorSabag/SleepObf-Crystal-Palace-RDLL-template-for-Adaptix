x64:
	load "bin/loader.x64.o"        # read the loader COFF
		make pic +gofirst          # turn it into PIC and ensure the go function is at the start

	run "services.spec"  # run the services spec to merge the services PIC and resolve functions

	run "pico.spec"  # run the pico spec to export the setup_hooks function and finalize the PIC
		link "pico"

	push $DLL       # read the dll being provided
		link "dll"  # link it to the "dll" section in the loader

	
	export  # export the final pic