x64:

  load "../../build/pico.x64.o"                                         # read the pico COFF
    make object +optimize +disco +mutate  
  
  load "../../build/hooks.x64.o"                                        # read the hooks COFF
    merge                             

  mergelib "../../crystal_palace/libtcg.x64.zip"

  exportfunc "setup_hooks" "__tag_setup_hooks"                          # export the hooks setup function for the loader to call
  exportfunc "set_image_info" "__tag_set_image_info"                    # export image info setter for Ekko obfuscation

  addhook "KERNEL32$WaitForSingleObjectEx" "_WaitForSingleObjectEx"     
  addhook "KERNEL32$WaitForSingleObject" "_WaitForSingleObject"         
  addhook "KERNEL32$WaitForMultipleObjects" "_WaitForMultipleObjects"                   
  addhook "KERNEL32$ConnectNamedPipe" "_ConnectNamedPipe"
  
  export