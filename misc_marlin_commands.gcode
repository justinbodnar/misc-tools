G91                  ; Put in relative mode
G1 Z10               ; Lower bed by 10mm
G90                  ; Put back in absolute mode
G1 X0 Y0             ; Zero (home) the X & Y
M104 S0              ; set temp to 0, assume user heats it up
M25                  ; Pause and wait for the user
M109 S225            ; heat back up before continuing
G91                  ; Put in relative mode
G1 Z-10              ; Raise the bed back up 10mm
G90                  ; Put back in absolute mode
