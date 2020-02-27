# Deobfuscate Junk Code

**D**e**o**bfuscate **J**unk Code (DOJ) is a simple IDA Pro plugin which tries to detect segments of junk code obfuscation.</br>
It has two main parts:

- A **heuristic** for finding where junk code starts. </br>
that code usually created using some 3rd party software, and contains varied long segments of instructions. </br>
My heuristic was looking for multiple rare x86 assembly instructions which aren't common in normal compiled code.</br>
The heuristic is independant of the next part, and could be easily expanded.
- Running that code in `unicorn` emulator while making register/memory snapshot on each instruction. That state is being checked for finding similar state.

## Screenshots

### Before

![](https://i.imgur.com/aFqm29H.png)</br>
![](https://i.imgur.com/cy6x0vI.png)

## After

![](https://i.imgur.com/EnCPROA.png)</br>
![](https://i.imgur.com/BP12S1j.png)

## Dependencies

- IDA Pro 7.4
- Python 3
- `pip install unicorn`