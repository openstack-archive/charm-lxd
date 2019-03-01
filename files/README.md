The `lxd` file in this directory is for building the lxd-dummy package which is
used to replace the proper `lxd` package when the snap is installed.  Use the
`equivs` package to build the dummy package.  Note as the dummy package is *in*
this directory it should never need rebuilding!

The commands to rebuild the package are (should it ever need to be version
bumped or other action):

```bash
$ sudo apt install equivs
$ equivs-build lxd
```

