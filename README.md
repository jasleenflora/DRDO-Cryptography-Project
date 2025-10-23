# DRDO Random Cipher Generator

A Python Tkinter application to generate random key streams using **stream and block ciphers**. This project was developed as part of a DRDO internship.

## Features

- Select between **Stream Cipher** or **Block Cipher**.

- Choose from multiple ciphers (e.g., RC4, A5/1, SM4, HIGHT, PRESENT).

- Enter a file size (in powers of 10) to generate random key streams.

- Generates **100,000 rows of 8-byte key streams**.

- Saves the generated key streams to a **CSV file**.

- View generated CSV content in a popup window.

- Simple and interactive **Tkinter GUI**.

## Installation

1. Clone the repository:
  
Navigate to the project directory:
cd DRDO_Random_Cipher_Generator
Make sure you have Python 3.x installed.
Install required packages (Tkinter comes pre-installed with Python):
pip install --upgrade pip

##How to Run

Run the main Python file:

python Cryptography_file.py

-Select a Cipher Type (Stream or Block).

-Select a specific cipher from the dropdown.

-Enter the file size (in powers of 10, e.g., 10, 100, 1000).

-Click Start to generate the random key stream CSV.

-A popup will appear showing the CSV content.

##Folder Structure

DRDO_Random_Cipher_Generator


cryptography_file.py           # Main Python Tkinter code


README.md                     # Project documentation

##Notes

-Generated CSV files are temporary and deleted after viewing in the popup.

-File size must be a positive power of 10 (10, 100, 1000, ...).
