---
title: "Chapter-18 PMA Write-up"
classes: wide
header:
  teaser: /assets/images/site-images/PMA_logo.jpg
ribbon: Black
description: "Chapter 18 write-up from Practical Malware Analysis Book"
categories:
  - Tutorials Summaries
toc: true
---

# Chapter 18 challenges the walkthrough

This chapter discussed packing and unpacking techniques.

# Lab16-1.exe <br>

### Packing identification:

With tools like **Detect it Easy** we can see that the entropy of this is very high `7.50329` and `DIE` identifies that the packer is `UPX`.

![](/assets/images/tutorials-summaries/Chapter18-PMA/Entropy.PNG)

Also with `PEview`, we can see that in `.text` the virtual size and size of raw data are very different.

![](/assets/images/tutorials-summaries/Chapter18-PMA/virtual-raw-sizes.PNG)

And also this sample has `UPX` section and this is an indicator to the packer.
Also, the import table has a few imports and all of them are indicators of packed files like `LoadLibraryA`, `GetProcAddress`, and `VirtualAlloc`.

### Looking at disassembly:

After loading the sample in IDA Pro and scrolling down to the end of the code we will see that the sample will make a jump to `byte_40154F` 
- this location is so far from the calling location and
- this jump at the end of the code 

So this jump may be the tail jump, let's take this location in `X64dbg` to see what is inside it.

We will see a lot of **add byte ptr ds:[eax], al**, and if we go to `00409F43` when the jump calling

![](/assets/images/tutorials-summaries/Chapter18-PMA/00409F43.PNG)

 and set a breakpoint on it and run the sample, we will get the original instructions:

![](/assets/images/tutorials-summaries/Chapter18-PMA/original-code.PNG)

Now, we can dump this code to analyze it, I will use `Scylla` to fix the import table and dump the process on the disk.

Now, we have the unpacked code and we can see imports `GetCurrentHwProfileA` and we can analyze it to know its functionality. 

![](/assets/images/tutorials-summaries/Chapter18-PMA/unpacked-malware.PNG)

---

