### PythonBasics TryHackMe

### Description: Using a web-based code editor, learn the basics of Python and put your knowledge into practice by eventually coding a short Bitcoin investment project.

### Task 1

```
# Write your python code here
print("Hello World")

b'THM{PRINT_STATEMENTS}'
```

### Task 2

```
print(21 + 43)
b'THM{ADDITI0N}'

print(142 - 52)
b'THM{SUBTRCT}' 

print(10 * 342)
b'THM{MULTIPLICATION_PYTHON}'

print(5**2)
b'THM{EXP0N3NT_POWER}'
```

### Task 3

```
height = 200
height = height + 50
print(height)
b'THM{VARIABL3S}'
```

### Task 4

```
"""
    In this project, you'll create a program that calculates the total
    cost of a customers shopping basket, including shipping.

    - If a customer spends over $100, they get free shipping
    - If a customer spends < $100, the shipping cost is $1.20 per kg of the baskets weight

    Print the customers total basket cost (including shipping) to complete this exercise.

"""

customer_basket_cost = 34
customer_basket_weight = 44

shipping_fee = 1.20
cost_shipping_fee = shipping_fee * customer_basket_weight
total_cost = customer_basket_cost + cost_shipping_fee   

if customer_basket_cost > 100:
    print("You get free shipping for purchasing this!!")
else:
    if customer_basket_cost < 100:
        print("Total cost")
        print(total_cost)

b'THM{IF_STATEMENT_SHOPPING}'


"""
    In this project, you'll create a program that calculates the total
    cost of a customers shopping basket, including shipping.

    - If a customer spends over $100, they get free shipping
    - If a customer spends < $100, the shipping cost is $1.20 per kg of the baskets weight

    Print the customers total basket cost (including shipping) to complete this exercise.

    ===> You've redeemed a hint. Replace the X's with code to complete this exercise.

"""

shipping_cost_per_kg = 1.20
customer_basket_cost = 101
customer_basket_weight = 44

if(customer_basket_cost >= 100):
  print('Free shipping!')
else:
  shipping_cost = customer_basket_weight * shipping_cost_per_kg
  customer_basket_cost = shipping_cost + customer_basket_cost
print("Total basket cost including shipping is " + str(customer_basket_cost))

b'THM{MY_FIRST_APP}'
```

### Task 5

```
i = 0

while i <= 50:
  print(i)
  i = i + 1

b'THM{L00PS_WHILE_FOR}'
```

### Task 6

```
"""
    In this project, you'll create a program that that tells
    you when the value of your Bitcoin falls below $30,000.

    You will need to:
    - Create a function to convert Bitcoin to USD
    - If your Bitcoin falls below $30,000, print a message.

    You can assume that 1 Bitcoin is worth $40,000

"""

investment_in_bitcoin = 1.2
bitcoin_to_usd  = 40000

def bitcoinToUSD(bitcoin_amount, bitcoin_value_usd):
    usd_value = bitcoin_amount * bitcoin_value_usd
    return usd_value


usd_value = bitcoinToUSD(investment_in_bitcoin, bitcoin_to_usd)

if usd_value <= 30000:
    print("Bitcoin dropped")
else:
    print("Bitcoin rised")

b'THM{BITC0IN_INVESTOR}'
```

### Task 7

```
flag = open('flag.txt', 'r')
print(flag.read())

b'THM{BITC0IN_INVESTOR}'
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
