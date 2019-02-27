= yaml =
title: Unimelb programming proficiency test
slug: unimelb-programming-proficiency-test
date: 27/02/2019
tags: uni
= yaml =

# Overview

The Semester 1, 2019 Unimelb programming proficiency test was held today. The test is a simple 90 minute test that allows students who acheived 75%+ to skip COMP10001 and enrol in COMP10002 straight away.

This year's test had 6 questions, 4 of them being simple function implementations, 1 being a short response question, and 1 being a slightly more challenging function implementation.

The questions were geared towards Python, although you were allowed to use any language you wanted as long as you indicated that on the answer sheet. I'm not completely sure how marks will be awarded, but the test stated on the front that inefficient algorithms won't be penalised.

### The questions

The questions below are how I recall them from the test. The wording may not be exactly the same and my sample solutions might have some mistakes in them.

## Question 1: Palindromes [15 marks]

Write a function `is_palindrome` that takes a string `word` and returns `True` if the word is a palindrome and `False` otherwise. A palindrome is a word that reads the same backward as forward, for example `madam` is a palindrome, but `programming` is not.

### Sample solution

```python
def is_palindrome(word):
  return word == word[::-1]
```

## Question 2: Framed Message [15 marks]

Write a function `frame` that takes a list of strings `wlist` and prints the message in a frame of asterisks `*` such that the longest word in the list is just touching the edges of the frames. For example:

```pyshell
> frame(['COMP10001', 'is', 'fun'])

***********
*COMP10001*
*is       *
*fun      *
***********
```

### Sample solution

```python
def frame(wlist):
    width = 2 + max(map(lambda w: len(w), wlist))
    print('*' * width)
    for w in wlist:
        print('*' + w.ljust(width - 2, ' ') + '*')
    print('*' * width)
```

## Question 3: Median Letter [15 marks]

Write a function `medianL` that takes a string `word` consisting of only lower case alphabet letters and returns a string with the median letter capitalised. The median letter in this case refers to the letter that sits above half of the letters and below the other half of the letters in the word. For example in the word `predict`, `d` is the median letter, and so `medianL('predict')` returns `preDict`. If the word has an even number of letters, the median letter is defined to be the rightmost letter of the two letters that exhibit the 'median' property. For example in the word `orange`, `n` is the median letter, and so `medianL('orange')` returns `oraNge`.

### Sample solution

```python
def medianL(word):
    m = len(word) // 2
    return word[:m] + word[m].upper() + word[m+1:]
```

## Question 4: Missing Letters [20 marks]

Write a function `missing_letters` that takes two strings `word1` and `word2` and returns a string containing the letters that need to be added to `word2` to make up `word1` (in the order they appear). Each character should only be considered once. For example, `missing_letters('classes', 'lass')` should return `ces`, and `missing_letters('woololomng', ol)` should return `woolomng`. An empty string should be returned if `word1` is the empty string as no additional characters can be added to `word2` to make up `word1`.

```python
def missing_letters(word1, word2):
    letters = ''
    for l in word1:
        if l not in word2:
            letters += l
        else:
            word2 = list(word2)
            word2.remove(l)
            word2 = ''.join(word2)
    return letters
```

## Question 5: Grid Words (challenging) [15 marks]

Write a function `valid_word` that takes two parameters: `board` and `word`, and returns True or False depending on whether or not `word` can be formed by connecting adjacent letters in the board. The board is represented as a 2 dimensional list of any size (n x m). An adjacent letter is a letter that is directly above, to the right, below or to the left of a letter.

For example, if the board is as given below, calling `valid_word` with the words `ABC` or `AESAG` would return `True`, while calling it with the words `CDE` or `ESACF` would return `False`

| **A** | **B** | **C** | **D** |
| -- |
| **E** | **S** | **A** | **C** |
| **F** | **E** | **G** | **A** |

### Sample solution

```python
def valid_word(board, word):
    w = len(board[0])
    h = len(board)

    def get_adjacent(r, c):
        return list(filter(lambda p: p[0] >= 0 and p[0] <= h-1 and p[1] >= 0 and p[1] <= w-1,
            [(r-1,c), (r, c+1), (r+1, c), (r, c-1)]))

    def valid_word_r(p, word):
        l = word[0]
        adj = get_adjacent(p[0], p[1])
        al = list(map(lambda a: board[a[0]][a[1]], adj))
        if l not in al: return False
        if len(word) == 1: return True
        np = [a for a in adj if board[a[0]][a[1]] == l]
        return any(list(map(lambda p: valid_word_r(p, word[1:]), np)))

    sp = [(i, r.index(word[0])) for i,r in enumerate(board) if word[0] in r]
    return any(map(lambda a: valid_word_r(a, word[1:]), sp))
```

Note: We were warned to only attempt this question after completing all of the other questions. I think this question was designed specifically to distinguish the students' capabilities. I think most people would have either spent around 30 to 40 minutes on this question or not attempted it at all.

## Question 6: Short Answer Responses [10 marks]

### Part A [4 marks]

How many multiplication operations occur in the following code for any given `M` and `N`?

```python
res = 0
for i in range(1, M+1):
  for j in range(1, M-N+1):
    res += i * j
```

### Sample solution

$((M+1)-1) \times ((M-N+1)-1)$
$= M^2 - MN$

### Part B [6 marks]

How many times does `Function` get called when called with the parameter `twydlyllyngy`?

```python
def Function(word):
  if len(word) == 0:
    return 0
  elif len(word) == 1:
    if word in 'aeiou':
      return 1
    else:
      return 0
  else:
    mid = int(len(word) / 2)
    return Function(word[:mid]) + Function(word[mid:])
```

### Sample solution

This is a binary search that ends only after all elements have been checked, hence the `Function` is called `23` times, including the initial call.