<h2> Stringer EchoCTF </h2>

### Difficulty = Advanced

### IP Address = 10.0.14.28

![image](https://user-images.githubusercontent.com/113513376/222299045-6d070678-3e7e-462b-bd7a-331dc1e7de86.png)

We're given a netcat server to connect to 

```
Connect: nc 10.0.14.28 1337
```

Connecting to it shows a server
![image](https://user-images.githubusercontent.com/113513376/222299398-824ab740-8554-47f4-b0bb-6292930243c5.png)

Giving it any input prints back its content
![image](https://user-images.githubusercontent.com/113513376/222299455-20f0de19-5f3d-44ea-9d4b-14a8021fb943.png)

From the box name `stringer` its likely a service which is vulnerable to format string vulnerability

Lets confirm it by leaking addresses off the stack using `%s`
![image](https://user-images.githubusercontent.com/113513376/222299567-2fee1d4f-2485-4a16-817a-26ed788053f5.png)

Cool we get a flag 

Now that we've confirmed its a format string vulnerability the idea is to start leaking off values off the stack till we get all flags needed

But obviously we can do this `%1$s` which will print the content of the first string offset  
![image](https://user-images.githubusercontent.com/113513376/222299814-85e58d16-2399-4605-af1f-7c70dfeb6dc8.png)

And we can keep on going on 
![image](https://user-images.githubusercontent.com/113513376/222299969-198fe8c3-4721-4848-9c8f-745f904fe83f.png)

Not all the offset will have a value stored in it but yet we can keep on leaking that way

Doing it manually sucks and its time wasting

So i made a script to help me do it

Here's my leak script [Leak]()
