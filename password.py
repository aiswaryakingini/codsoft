import tkinter as tk
from tkinter import *
import random

def generate_password():
    try:
        length = int(textbox.get())
    except ValueError:
        result_text.delete(1.0, END)
        result_text.insert(END, "Please enter a valid number for length.")
        return

    complexity = complexity_var.get()

    if complexity == "High":
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*'
    elif complexity == "Medium":
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    else:
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    password = ''.join(random.choice(chars) for _ in range(length))
    
    result_text.delete(1.0, END)
    result_text.insert(END, password)

root = tk.Tk()
root.title("PASSWORD GENERATOR")
root.geometry("450x450")
root.configure(bg='#1C2833')

main_frame = tk.Frame(root, bg='#2E4053', bd=10, relief="groove")
main_frame.place(relx=0.5, rely=0.5, anchor=CENTER, width=350, height=350)

frame = tk.Frame(main_frame, bg='#2E4053')
frame.pack(pady=10)

label = tk.Label(frame, text="Length of Password", font=("Arial", 14, 'bold'), bg='#F7DC6F', fg='#333')
label.pack(side=LEFT, padx=5)

textbox = tk.Entry(frame, font=("Arial", 14), width=10, bg='#fff', fg='#333')
textbox.pack(side=LEFT, padx=5)

frame1 = tk.Frame(main_frame, bg='#2E4053')
frame1.pack(pady=10)

label = tk.Label(frame1, text="Complexity", font=("Arial", 14, 'bold'), bg='#F7DC6F', fg='#333')
label.pack(padx=5, pady=5)

complexity_var = StringVar(value="Low")

radiobutton_high = tk.Radiobutton(frame1, text="High", variable=complexity_var, value="High", font=("Arial", 14), bg='#2E4053', fg='#F7DC6F', selectcolor='#2E4053')
radiobutton_high.pack(anchor=W, pady=2)

radiobutton_medium = tk.Radiobutton(frame1, text="Medium", variable=complexity_var, value="Medium", font=("Arial", 14), bg='#2E4053', fg='#F7DC6F', selectcolor='#2E4053')
radiobutton_medium.pack(anchor=W, pady=2)

radiobutton_low = tk.Radiobutton(frame1, text="Low", variable=complexity_var, value="Low", font=("Arial", 14), bg='#2E4053', fg='#F7DC6F', selectcolor='#2E4053')
radiobutton_low.pack(anchor=W, pady=2)

button = tk.Button(main_frame, text="Generate", font=("Arial", 14, 'bold'), bg='#4CAF50', fg='#fff', command=generate_password)
button.pack(pady=10)

result_text = tk.Text(main_frame, font=("Arial", 14), width=30, height=5, bg='#fff', fg='#333')
result_text.pack(pady=10)

root.mainloop()
