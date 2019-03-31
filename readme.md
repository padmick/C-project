## C Project for Theory of Algorithms 
## Padraic Wade
## G00314523

# How to build and use:
via gcc you would pass:

`gcc -o sha256 -g     -std=c11     sha256.c`

Then running:

`./sha256` 

Should trigger the app to run:

The application reads in a local 'input.txt' file and from that displays the 256 sha in the display.

Depending on your enviorment you may need to pipe your output to cat to read it (I had issues reading it in the WSL until i fed it to cat).