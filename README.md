# Python implementation of a Sysinternals Dbgview client

Compatible with Python 3.5+

### Example usage

 - Launch Sysinternals Dbgview in agent mode
 
```
C:\Sysinternals>Dbgview.exe /a
```

 - Connect to localhost and listens for messages

```
$ python dbgview_client.py connect localhost
INFO:__main__:connected!
```

 - Send a message

```
C:\>python dbgview_client.py print "It works!"
```

 - Receive something like the output below

```
[1][2019-04-29 21:31:07.566000][0.00000][13864] It works!
```

### See also

- https://docs.microsoft.com/en-us/sysinternals/downloads/debugview
- https://github.com/CobaltFusion/DebugViewPP
