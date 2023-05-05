---
title: "Chapter-16 PMA Write-up"
classes: wide
header:
  teaser: /assets/images/site-images/PMA_logo.jpg
ribbon: Black
description: "Chapter 16 write-up from Practical Malware Analysis Book"
categories:
  - Tutorials Summaries
toc: true
---

# Chapter 16 challenges the walkthrough

This chapter discussed Anti-debugging techniques.

# Lab16-1.exe <br>

Analyze the malware found in Lab16-01.exe using a debugger.

### Q1- Which anti-debugging techniques does this malware employ?

If we open this malware in `x64dbg` and go to main function we will see that this malware will get the `PEB` structure and then get `(BeingDebugged , ProcessHeap , NtGlobalFlag)` flags to check the existence of the debugger.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab1/Anti-Debugging.png)

---

### Q2- What happens when each anti-debugging technique succeeds?

As we can see in the image above, if any anti-debugging checking succeeds there is a call to `sub401000`. If we examine this function

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab1/Delete_file.PNG)

As we can see this function will get our binary path and then pass it and `/c del` argument to `ShellExecute` function. So, if the malware notice that there is a debugger, it will delete itself.

---

### Q3- How can you get around these anti-debugging techniques?

We can modify conditional jump instructions to the opposite one, so, we can convert `jz` to `jnz` and vice versa. Or we can change the `ZF` after each comparison.

---

### Q4- How do you manually change the structures checked during runtime?

We can modify PEB flags by right click on their location for example the malware uses `eax` to hold PEB address and then accesses `offset 0x2` to get `BeingDebugged` flag, so, we can click on `[eax+2]` and follow it on the memory dump and edit the value to whatever we want. Or we can simply type this command `dump fs:[30] + 2` on the command window in the debugger and the debugger will take us to this offset.

---

### Q5- Which OllyDbg plug-in will protect you from the anti-debugging techniques used by this malware?

For me, I use x64dbg and I use `ScyllaHide` plug-in to avoid debugging detection.

---
---

# Lab16-2.exe <br>

Analyze the malware found in Lab16-02.exe using a debugger. The goal of this lab is to figure out the correct password. The malware does not drop a malicious payload.

### Q1- What happens when you run Lab16-02.exe from the command line?

The malware will ask me to put in a 4-character password.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/run-without-params.PNG)

---

### Q2- What happens when you run Lab16-02.exe and guess the command-line parameter?

If we try a random password like `abcd`, the malware will print `Incorrect password, Try again.`

---

### Q3- What is the command-line password?

If we open this malware in IDA, we will find that it will create a thread called `StartAddress` which will write content in `str2`, and then it will take our parameter and compare two values.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/maybe-password.PNG)

If we try to debug this code in IDA and see what will be put in str2, we will see that it will contain a value of `bzqr` 

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/first-impresion-password.PNG)

If we try to enter it as a password, it will print an incorrect password also. So, we need to go deep inside this malware to figure out what is the correct password.

---

### Q4- Load Lab16-02.exe into IDA Pro. Where in the main function is strncmp found? 

strncmp located at `0040123A`

---

### Q5- What happens when you load this malware into OllyDbg using the default settings?

I use x64dbg, but I figure out what is going on.

When we usually run a binary in the debugger, the debugger first goes to `Entry point` of this binary.

But, in this malware, the x64dbg goes to function before reaching the malware's entry point. This is an indication that this malware may be using `TLS callbacks`. 

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/TLS_in_x64.PNG)

To ensure that this malware uses this technique or not, we can check the PE header in any PE parser tool like `PEview` or `PE-bear`

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/TLS_in_PE-bear.PNG)

As we can see the addresses of the TLS callback in x64dbg and PE-bear are identical.

If we try to open this malware in ollydbg because of this TLS callback the malware will terminate itself.

---

### Q6- What is unique about the PE structure of Lab16-02.exe?

This malware has a TLS section in its PE header.

---

### Q7- Where is the callback located? (Hint: Use CTRL-E in IDA Pro.)

As we find in x64dbg and PE-bear, the TLS located at `401060`

---

### Q8- Which anti-debugging technique is the program using to terminate immediately in the debugger and how can you avoid this check?

If we look at TLS callback in IDA, we will see that this malware will check for any window named `OLLYDBG` using `FindWindowA` API.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/OLLYDBG-detection.PNG)

If the malware doesn't find any window with this name it will check on `arg_4` if it equals `2` it will try another anti-debugging technique which is `OutputDebugStringA`.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/OutputDebugStringA.PNG)

if the malware passes all checks it will go to the main and execute its mal code.

We can avoid these techniques by first making our debugger breaks on TLS callbacks and then we can edit conditional jumping on it, and we can use `ScyllaHide` plug-in to avoid the techniques implemented in this callback.

---

### Q9- What is the command-line password you see in the debugger after you disable the anti-debugging technique?

If we return to the main in IDA, as we say above there is a thread called `StartAddress` will put a value in `str2` which is `bzqr`, if we enter this value as a parameter to this file and debug it, it will accept it. But, if we type this password in a command line it will print that this password is incorrect. So, we can predict that `StartAddress` has an anti-debugging technique to confuse us. 

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/anti-debugging-password.png)

So, let's see what is inside it.

Inside `StartAddress` there is an encoding routine, but also there is access to `PEB` structure especially offset `2`.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/anti-debugging-StartAddress.PNG)

And if the value of this flag = 1 it will produce the password `bzqr`, but if we edit the flag value to be 1, the malware will produce a password which is `bzrr`

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab2/right-password.PNG)

And if we try to type this password in the command line, the malware will print that the password is correct.

---

### Q10- Does the password found in the debugger work on the command line?

The password we found in the debugger `bzqr` doesn't work on the command line.

---

### Q11- Which anti-debugging techniques account for the different passwords in the debugger and on the command line, and how can you protect against them?

Inside the function that will produce the password to compare it will apply `BeingDebuuged` checking to see if there is a debugger or not.

We can protect against this technique by using a `ScyllaHide` plug-in or manually modifying the flag value. 


---
---

# Lab16-3.exe <br>

Analyze the malware in Lab16-03.exe using a debugger. This malware is similar to Lab09-02.exe, with certain modifications, including the introduction of anti-debugging techniques. If you get stuck, see Lab 9-2.

### Q1- Which strings do you see when using static analysis on the binary?

If we get the hardcoded string inside this malware we will find some APIs can be used for anti-debugging techniques like `GetTickCount` and another for network connections like `WSASocketA` and the last ones seems that this malware will delete itself if it notices the debugger.

```
Sleep
GetTickCount
GetModuleFileNameA
QueryPerformanceCounter
ShellExecuteA
WSASocketA
ExitProcess
TerminateProcess
cmd.exe
>> NUL
/c del 
```

---

### Q2- What happens when you run this binary?

Nothing, the malware will terminate immediately.

---

### Q3- How must you rename the sample in order for it to run properly?

If we load this malware into IDA, we will find that the malware will construct a string and then compare this string with the file name and if they was not identical the malware will exit.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/Correct_file_name.PNG)

Then the malware will compare its name with `str1` which is `ocl.exe`.

If we rename our sample to `ocl.exe` it also will do nothing.

If we scroll down in the code we will find that the malware will push `str1` as a parameter to `sub_4011E0` if we step over this function and see what is inside `str1` we will find that a different value loaded into it `qgr.exe`. So, let's go deep inside this function and see what happened.

The first thing we will notice inside this function is that it will call `QueryPerformanceCounter` and then in this function, the malware will generate an exception.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/sub_4011E0.png)

Then it will call `QueryPerformanceCounter` again and subtract the second return value from the first return value and compare the difference with `4B0h` 

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/anti-debugging_1.PNG)

If the difference is greater than the value it will move `2` to  `[ebp+var_118]` which is initialized to be 1 at the start of the function. 

After that, we will see that this is an encoding routine to convert `ocl.exe` to `qgl.exe`

If we NOPing this instruction which moves 2 to [ebp+var_118] and debugs the code, the encoding will produce another name `peo.exe` 

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/New_Name.png)

So, now we have three names we can rename our malware to it.

If we try the three names the last one `peo.exe` will run properly.

So, we can change the `jle` instruction in `sub_4011E0` to `jg` or NOPing the move instruction to get the correct file name.

---

### Q4- Which anti-debugging techniques does this malware employ?

For this point, this malware uses `QueryPerformanceCounter` as an anti-debugging techniue. But if we go deep in the main function we will find more techniques used.

After the file name comparison succeeds, the malware will set up a network connection using `WSAStartup` and `WSASocketA`, then at location `loc_401584` there is a suspicious logic performed.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/sub_401000.PNG)

The malware will call `GetTickCount` and then call `sub_401000` and then `GetTickCount` again.

If we go to inside `sub_401000` we will see almost the same logic in `sub_4011E0` it will generate a divide by zero exception.

After this function returns, the abstraction between the return value from the first GetTickCount and the second one will be performed and compare the difference with 1 and if the difference is below or equal it will continue, but if not they are some logic on `004015B2` to xor `eax` and load the value on `edx` on the effective address of `eax` and then return from main.

This logic will cause an `access violation exception` which will crash the process.  

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/access-violation-exception.PNG)

So, we can avoid this technique by modifying `jbe` with the opposite one.

After bypassing this check, the malware will call `sub_401300` which will also generate a divide by zero exception and if we pass this exception to the program to handle it, it won't handle it and the malware will be deleted.

So, let's go inside this function and see what happened.

As we know this function will generate a divide by zero exception but after and before exception generation, the malware will call `rdtsc` instruction twice at locations `(00401323 , 0040136D)` then it will get the difference and compare it with `7A120h` and if the difference is above it will call `sub_4010E0`

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/rdtsc.PNG)

If we take a look in sub_4010E0, we will see the delete logic to delete the file.

![](/assets/images/tutorials-summaries/Chapter16-PMA/Lab3/Delete_file.png)

So, if this technique notices the debugger existence it will delete the file.

---

### Q5-  For each technique, what does the malware do if it determines it is running in a debugger?

- The first technique will confuse you by comparing the file name with `qgr.exe`, so, if you would rename the malware with this name it won't run without the debugger.

- The second technique will cause an access violation exception and crash the process.

- The third technique will delete the malware from the desk.

---

### Q6- Why are the anti-debugging techniques successful in this malware?

I think because these techniques plays on time and all of them generate an exception, so, if the malware running under the debugger it will be detected.

---

### Q7- What domain name does this malware use?

By turning on `WireShark` on `Remnux` with `inetsim` we can see that after all debugger checks passed the malware will try to connect to `adg.malwareanalysisbook.com`

---
---
