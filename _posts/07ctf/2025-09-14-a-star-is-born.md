---
title: "07CTF – A Star Is Born Challenge"
date: 2025-09-14
categories: [CTFs, 07CTF]
tags: [misc]
hidden: true
---
## Challenge Details
-   Name: A Star Is Born
-   Category: Misc

**The challenge provides two files:**
-   `chal.mp3`

* * * * *
## Challenge description
<p style="font-size:14px;">
My friend has always dreamed of being a rockstar. Unfortunately, he's always been a poor musician. But do you know what my friend is really good at? Working with AI. He sent me his latest composition and mentioned that he hid a little surprise in it.
Can you figure out what he hid?
</p>
<p style="font-size:15px;">
Flag format: drgn{.*}
</p>

* * * * *
## Solution
The challenge provides an `MP3` file. The first step in any steganography challenge is to examine the file's properties and metadata. 

Sometimes, clues are hidden in plain sight.
By viewing the file details using a tool like `exiftool`, we can inspect the metadata tags. In this case, the "Album" tag immediately stands out.

![](/assets/img/07ctf/star1.png)
*Album   : MW10aDNwNHNzdzByZA==*
The "Album" field contains a `base64` encoded string: `MW10aDNwNHNzdzByZA==`

Putting it on [CyberChef](https://cyberchef.io/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=TVcxMGFETndOSE56ZHpCeVpBPT0) gave me this `1mth3p4ssw0rd` 

This leads to the hypothesis that there is a password-protected file, like a ZIP archive, embedded within the chal.mp3 file, and this is the password required to access it.

Running `binwalk` on the `chal.mp3` file gave me exactly what I was looking for:

![](/assets/img/07ctf/star2.png)
*embeded zip file which contains lyric.txt*

With the starting offset of the `ZIP` file identified, the next step was to extract it. I used the `dd` command to carve the data from the `MP3` file, starting from the specified offset `3809408` *(the start of the ZIP)*, and save it into a new file called `hidden.zip`

```
dd if=chal.mp3 of=hidden.zip bs=1 skip=3809408
```

Finally, I unzipped the newly created `hidden.zip` file using the password I had found earlier. This successfully extracted a file named `lyric.txt`. Inside, I found what appeared to be a `rockstar` code.

Snippet from lyric.txt:
```
The code is a attractive monstrosity
Knock the code down scream it
The code is a prestigious song
Say the code

The program's advancement obliterate him
Print the program
Scream like a maintenance revolution
The developper was gone
...
```
To run this code, I used the online interpreter at [codewithrockstar](https://codewithrockstar.com/online). I pasted the contents of the file into the editor and executed it.
The program's output was a series of numbers, which I recognized as ASCII decimal values.

![](/assets/img/07ctf/star3.png)

And finally I used a simple python script to convert those asci numbers to characters:

```python
nums = [100,114,103,110,123,122,48,117,114,101,95,116,104,51,95,114,48,99,107,115,116,97,114,125]
text = "".join(chr(n) for n in nums)
print(text)
```
## Flag
*drgn{z0ure_th3_r0ckstar}*

[⬅ Back to 07CTF Writeups](/posts/07CTF-writeups/)

