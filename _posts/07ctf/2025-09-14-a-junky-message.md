---
title: "07CTF – A junky message Challenge"
date: 2025-09-14
categories: [CTFs, 07CTF]
tags: [crypto]
hidden: true
---

## Challenge Details:
-   Name: A junky message
-   Category: Crypto

**The challenge provides two files:**
-   `a_junky_msg.txt`
* * * * *
## Challenge description
<p style="font-size:14px;">
What??, is this supposed to be morse?
</p>

## Solution
The challenge started with a single text file and a taunting question. Inside was not a message, but a chaotic mess of symbols: dots, dashes, tildes, and equals signs.

```
==--=.___~.__=~._===~.__._=~.=~-__-_===._~-__===~-==-___=~.__~-_===._~._=._=~._==-_===-__=._=~-=~._===-__~.==~-__~.___===._==~._===~-___===.__=~.__===.-___===-__.___~._===-==-_==-_=-___==~.__~-==~-__.=-_=~-__===~._~-_===-___===~-__=-~.==-__-_===~.__-__-__=-===.__===.__==~.___-__~-___===~.___==~._===~-_===-___=.___==-_=._=-_~-__===-_=-___==~-__==.=~-__===.__.__===~-__~-=.___=~-__=.__~.___=-___===-_~._==-___~.__==~.__===~.__===-===-._-_~-===~-__==.___==.__=-__==~-_===-_.__==.___=~-__==-_~.__-___=.___=-__=-__==~-_=~-___=-_===~._==.___~-_==-__==~.==-__~-___===-===~.__~-=~-_==-_~..__-__.__==._=~._==~-__==~-==~.___===-___=~.___=.__==._==~-_-__==~-==._===.__==~-_===~-___~._~-_=-_===~._==~-__==~.___=~.__~.__~._=-=.~-_~-_==-_===~-_=-___~.~.___~-==~-___.___==.__===.___~._=~.___==._==-__===~-_==.___=~-__=-_-__~._===~-_=~-_._=-__=.==.___===._=~._==-__==~-__=~._==~.__===-___==.___~-=.__===~-__===~.__==~-_===~._.__==~-_~._==.===-___-__==~-___~..__===-__===-__=.__=-___=.___===-__=~-==-~-_-_~.___==-___==-_=~-__===~.___===~-__===~.__._=.__=~-___~-___=-_=~._._=~-~.___==.__===._=-_=-___===~.__=~.__===~-===-==~.-___~-_=.__=~.___==~.==~._~-__===.___===~-__=-_=-__===~._~.__~-_===~-===~.__-_=~.__==-===~._===~-__==~._==~-_=.___~-__===-__=-_=~.===.__~-__===~._===._==._==~-_===-___===~.___==.=-__=~-___==._===-===~-__~--=~-_===~.__=~-___
```

Using [morsecode.world](https://morsecode.world/international/translator.html), my first instinct was to clean up the "junk." Surely, the `~` and `=` symbols were just noise, designed to obscure a real Morse message. I meticulously stripped them all away, hoping to reveal a clean sequence of dots and dashes. 

Nothing. The output was invalid. It was complete gibberish. *This wasn't just noisy Morse; it was something else entirely.*

Feeling stuck, I turned to a few LLMs for ideas. My initial, broad queries like "decode this message" were fruitless; they couldn't make sense of the string either. I changed my approach. I began asking more targeted questions about encoding techniques.

### Solution script

The LLM's response listed several possibilities, but one stood out: `binary representation`. The suggestion was that two of the characters could represent `1` and `0`, while the others were simply distractors to be ignored.

```python
# decoder.py

data = "--.___.__._.__._.-__-_._~-__===~-==-___=~.__~-_===._~._=._=~._==-_===-__=._=~-=~._===-__~.==~-__~.___===._==~._===~-___===.__=~.__===.-___===-__.___~._===-==-_==-_=-___==~.__~-==~-__.=-_=~-__===~._~-_===-___===~-__=-~.==-__-_===~.__-__-__=-===.__===.__==~.___-__~-___===~.___==~._===~-_===-___=.___==-_=._=-_~-__===-_=-___==~-__==.=~-__===.__.__===~-__~-=.___=~-__=.__~.___=-___===-_~._==-___~.__==~.__===~.__===-===-._-_~-===~-__==.___==.__=-__==~-_===-_.__==.___=~-__==-_~.__-___=.___=-__=-__==~-_=~-___=-_===~._==.___~-_==-__==~.==-__~-___===-===~.__~-=~-_==-_~..__-__.__==._=~._==~-__==~-==~.___===-___=~.___=.__==._==~-_-__==~-==._===.__==~-_===~-___~._~-_=-_===~._==~-__==~.___=~.__~.__~._=-=.~-_~-_==-_===~-_=-___~.~.___~-==~-___.___==.__===.___~._=~.___==._==-__===~-_==.___=~-__=-_-__~._===~-_=~-_._=-__=.==.___===._=~._==-__==~-__=~._==~.__===-___==.___~-=.__===~-__===~.__==~-_===~._.__==~-_~._==.===-___-__==~-___~..__===-__===-__=.__=-___=.___===-__=~-==-~-_-_~.___==-___==-_=~-__===~.___===~-__===~.__._=.__=~-___~-___=-_=~._._=~-~.___==.__===._=-_=-___===~.__=~.__===~-===-==~.-___~-_=.__=~.___==~.==~._~-__===.___===~-__=-_=-__===~._~.__~-_===~-===~.__-_=~.__==-===~._===~-__==~._==~-_=.___~-__===-__=-_=~.===.__~-__===~._===._==._==~-_===-___===~.___==.=-__=~-___==._===-===~-__~--=~-_===~.__=~-___"

# 1. Keep only '.' and '-'
filtered = ''.join(c for c in data if c in ['.', '-'])

# 2. Map to binary
binary = filtered.replace('-', '1').replace('.', '0')

# 3. Drop first 6 bits (padding)
binary = binary[6:]

# 4. Split into bytes and convert to ASCII
chars = []
for i in range(0, len(binary), 8):
    byte = binary[i:i+8]
    if len(byte) == 8:
        chars.append(chr(int(byte, 2)))

decoded = ''.join(chars)
print("Filtered bits:", binary)
print("Decoded text:", decoded)
```

![](/assets/img/07ctf/junk2.png)

### Flag

*7CTF{on3_M4ns_7r4sh_07heRs_tr3asUr3}*

[⬅ Back to 07CTF Writeups](/posts/07CTF-writeups/)
