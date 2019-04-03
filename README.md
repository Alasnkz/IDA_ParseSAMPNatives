# IDA_ParseSAMPNatives

## What is this?
This is a IDA python script to automatically parse SA-MP natives for easy use in IDA.

## I don't really know what this is, got a picture?
Sure!

![](https://cdn.discordapp.com/attachments/485181355710349323/561574449451761666/unknown.png)

## How do I use this?
File -> Script File in IDA assuming you have python installed.
Make sure to edit the script to point it to your include directory:
`ImportNativeArgumentsToIDA("LINK INCLUDE FOLDER HERE")`
to (for example):
`ImportNativeArgumentsToIDA("C:\\mygreatserver\\pawno\\include\\")`

## I can fix something, can I contribute?
Of course, submit a PR and I'll respond in no time.

## Bugs
Some natives won't automatically have the native paramater structure assigned to them.
Some natives that assign values to references may seem to be overwriting the param_count structure member when they are not.

## Other useless notes/mentions.
Sorry for the really messy code! I was doing this at 1am-4am in the morning some days ago. 
This was only tested on IDA 7.0.