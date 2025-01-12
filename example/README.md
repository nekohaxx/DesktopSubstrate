To run this example:

```
$ gcc exec.c -o exec
$ gcc bar.c -shared -o bar.so
$ ./exec
The number is: 1337
$
```

Compile the hook and run it:

```
$ gcc hook.c ./bar.so -shared -o hook.so -I ../include -fPIC
$ LD_PRELOAD=./hook.so:../substrate.so
The number is: 1338
$
```
