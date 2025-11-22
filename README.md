# p-ku-23

Python Implementation of KU23: Honest-Majority Threshold ECDSA with Batch Generation of Key-Independent Presignatures

## Intro

Just how good is Gemini 3?  
In this paper, [Honest-Majority Threshold ECDSA with Batch Generation of Key-Independent Presignatures](https://eprint.iacr.org/2024/2011), Jonathan Katz and Antoine Urban from [Dfns](https://www.dfns.co/) describe an efficient protocol for honest-majority threshold ECDSA supporting batch generation of key-independent presignatures that allow for "non-interactive'" online signing.  

With the release of [Gemini 3](https://blog.google/products/gemini/gemini-3/), I wanted to test Code-Generation-From-PDF... this repo is the result of this experiment.

## Prior Experiments

Ilyes and I have worked on some successful experiments such as [P12](https://github.com/tjdragon/Part-12-Computation), a Zero-Knowledge Enhanced Threshold ECDSA Signature System, using LLMs, from text to code, re-doing the [maths](https://github.com/tjdragon/Part-12-Computation/blob/main/Maths/readme.md) as part of the learning process.

This time, I decided to go straight from the pdf to the code!

## How

The process is as follows:

1. Download the [PDF](https://eprint.iacr.org/2024/2011) an upload it to Gemini 3
2. I used the following prompt: "Summarize the pdf" - idea is to get a high level overview of the paper
3. Then the next prompt: "Please implement a python code that demonstrates a 2 out of 3 signature scheme using the protocol from the paper"

The first generated code was [uk23demo.py](uk23demo.py).
I then asked to use proper cryptographic libs, resulting in [uk23demo_secure.py](uk23demo_secure.py).

How long did it take?  Just below 30 minutes...
