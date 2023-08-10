---
title: "0xL4ugh CTF 23"
classes: wide
header:
  teaser: /assets/images/site-images/0xl4ugh_ctf.jpg
ribbon: DodgerBlue
description: "0xL4ugh ctf 23 RE challenges"
categories:
  - Reverse Engineering
toc: true
---


# 0xL4ugh CTF 23 - RE Challenges Writeup

### Team: Br00f0rs3rs
---

## 1- Easy-Peasy:

When we run this file it will ask us to enter the flag. 

![](/assets/images/reverse-engineering/0xl4ugh/Easy-first-run.PNG)Easy-first-run.PNG

So let's look at disassembly in IDA.

Looking at strings in IDA to get "Enter The Flag" string.

![](/assets/images/reverse-engineering/0xl4ugh/Easy-String.PNG)

Going to function that used the string and exploring it.

![](/assets/images/reverse-engineering/0xl4ugh/Easy-main.PNG)

Simple code, it will print the string and receive the input and then compare **[rbp+var_18]** with **1Ah** which is 26 and if not equal it will go to print **"This will not work"**. So the first thing is our right flag must be 26 characters.
After checking the length, it will looping on our input and make some math logic to check if this input is the right flag or not.

![](/assets/images/reverse-engineering/0xl4ugh/Easy-loop.PNG)

So, let's convert to x64dbg to debug this loop.


![](/assets/images/reverse-engineering/0xl4ugh/Easy-Algo.PNG)

The algorithm is very simple it will take each char and reverse its ASCII code and compare it with the value, the first value is **64** so to know the right char we will reverse it and convert to decimal and we Will get **F**.

After finishing the debugging we will get these hex codes:
>> [46 c4 41 47 7b 43 50 50 5f 31 53 5f 43 30 39 6c f5 32 34 35 32 37 34 35 36 7d]

After converting it we will get the flag

>> FLAG{CPP_1S_C00l_24527456}

---
---

## 2- Sneak:

![](/assets/images/reverse-engineering/0xl4ugh/Sneak-code.PNG)

This challenge was python bytecode and It was my first time facing this shape of code so I used the python bytecode instructions manual and start to translate it into python code 

>> Instructions: http://vega.lpl.arizona.edu/python/lib/bytecodes.html

Python code after translating:

``` 
import base64

from cryptography.fernet import Fernet

encMessage = 'gAAAAABj7Xd90ySo11DSFyX8t-9QIQvAPmU40mWQfpq856jFl1rpwvm1kyE1w23fyyAAd9riXt-JJA9v6BEcsq6LNroZTnjExjFur_tEp0OLJv0c_8BD3bg='

key_bytes = base64.b64decode('7PXy9PSZmf/r5pXB79LW1cj/7JT6ltPEmfjk8sHljfr6x/LyyfjymNXR5Z0=')

key = []

for k_p in key_bytes:
    key.append(k_p ^ 160)

key = bytes(key)

fernet = Fernet(key)

decMessage = fernet.decrypt(encMessage)

print (decMessage)

```

So running this code and you will get the flag

>> FLAG{FLY_L1k3_0xR4V3N}
