To run this example:

```
$ gcc bar.c -shared -o bar.so
$ gcc exec.c ./bar.so -o exec
$ ./exec
The number is: 1337
$
```

Compile the hook and run it:

```
$ gcc hook.c ./bar.so -shared -o hook.so -I ../include -fPIC
$ LD_PRELOAD=./hook.so:../substrate.so ./exec
The number is: 1338
$
```
