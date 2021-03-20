# password-vault
A simple password vault in Python3. THIS SHOULD NOT BE USED FOR REAL DATA

## Overview

This is a simple password vault, implemented in Python 3. It was written for the purpose of the Cryptography class in the Master's of Science in Cybersecurity Engineering at University of San Diego. As such, I highly reccommend that you do _not_ use this for any real passwords. On top of the fact that I wrote most of this in a single weekend, there are much more feature rich password managers available at no cost. Use one of those.


## System Objectives

As a password manager, there are two primary requirements of the system. Users must be able to:

1. Store a username and password for any website
2. Retrieve the username and password for a given website


There are also two major security requirements:

1. Passwords cannot be accessed by unauthorized parties
2. A user must have one high-entropy password to store and retrieve passwords


## Design

TBD