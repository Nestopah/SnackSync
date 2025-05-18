import tkinter as tk

root = tk.Tk()
root.title("Sample App")
root.geometry("300x200")
label = tk.Label(root, text="Hello, World!")
label.pack(pady=20)
root.mainloop()
