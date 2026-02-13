x64:

  load "bin/pico.x64.o"         # read the pico COFF
    make object

  load "bin/hooks.x64.o"         # read the hooks COFF
    merge

  mergelib "libtcg.x64.zip"

  exportfunc "setup_hooks" "__tag_setup_hooks"  # export the hooks setup function for the loader to call
  exportfunc "set_image_info" "__tag_set_image_info"  # export image info setter for Ekko obfuscation

  addhook "KERNEL32$Sleep" "_Sleep"  # hook Sleep to demonstrate the hooking capabilities of the loader

  export