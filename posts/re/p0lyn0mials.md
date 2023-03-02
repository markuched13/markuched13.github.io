<h3> Reverse Engineering </h3>

### Attack CTF 2022

### Chall Name: S0Lving_p0lyn0mials_OR_bRuteF0rcing

We're given a python file 
![image](https://user-images.githubusercontent.com/113513376/222312353-4416326d-6715-4dff-9302-535f36df72f4.png)

```
def my_function(x):
    return pow(x,3)+10*pow(x,2)+x*7 + 6

plaintext = "AtHackCTF{}"

cipher = []
for i in plaintext : 
   cipher.append(my_function(ord(i)))
print("cipher = " ,cipher)
```

Looking at the code we can tell what it does:

```
1. Creates a function which does a mathematical calculation
2. Stores the value `AtHackCTF{}` in variable plaintext
3. Then it loops through each character of plaintext 
4. It then calls the math function using the numerical value of the looped character as an argument
```

Running it creates an array of the encrypted value
![image](https://user-images.githubusercontent.com/113513376/222312807-c9e06fcb-2fd7-46c0-902a-bf86e3bc7cd3.png)

We're given the flag but in its encrypted form
![image](https://user-images.githubusercontent.com/113513376/222312923-ed981882-e643-442a-96b0-b4bfbdf8526a.png)

So with this the idea is to reverse it

And how it can be done is by looping through the numerical value of range about 300 then check if the cipher is equal to the value of the math function calculated

If it is then it should print the number and get its corresponding ascii value

Doing it manually isn't fun so i'll write a script to do that for me


