import tkinter as tk
import customtkinter


class GatewaySelectPage(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)
        
        label = tk.Label(self, text="Select Gateway Server")
        label.pack(pady=10, padx=10)

        button2 = tk.Button(self, text="Select",
                            command= controller.select_gateway)
        
        button2.pack()



class RegistrationPage(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        title = customtkinter.CTkLabel(self, text="Registration", text_color="#6225E6", height=50, width=50)
        title.pack()

        self.config(bg="black")

        clientname_label = customtkinter.CTkLabel(self, text="Client Name")
        clientname_label.pack()
        clientname_entry = customtkinter.CTkEntry(self, placeholder_text="Client Name", fg_color="#fff")
        clientname_entry.pack()

        password_label = customtkinter.CTkLabel(self, text="Client Password")
        password_label.pack()
        password_entry = customtkinter.CTkEntry(self, placeholder_text="Password", fg_color="#fff", text_color="black")
        password_entry.pack()

        #email
        email_label = customtkinter.CTkLabel(self, text="Client E-Mail")
        email_label.pack()
        email_entry = customtkinter.CTkEntry(self, placeholder_text="Email", fg_color="#fff")
        email_entry.pack(pady=(0, 50))

        button = customtkinter.CTkButton(self, text="Register",
                                command=controller.send_register_data, fg_color="#6225E6", hover_color="white")

        button.pack(pady=(0, 20))
        


class ModelSelectPage(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        self.config(bg="black")

        title = customtkinter.CTkLabel(self, text="Model Selection", text_color="#6225E6", height=50, width=50)
        title.pack(pady=(0, 30))

        button1 = customtkinter.CTkButton(self, text="Back",
                                command=lambda: controller.show_frame(RegistrationPage), fg_color="#6225E6")
        button1.pack(pady=(0, 50))

        button2 = customtkinter.CTkButton(self, text="Start",
                                command=controller.select_ml_model, fg_color="#6225E6")

        
        button2.pack()



class ValidationPage(tk.Frame):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent)

        label = tk.Label(self, text="Client Validation")
        label.pack(pady=10,padx=10)

        progressbar = customtkinter.CTkProgressBar(self, orientation="horizontal")
        progressbar.pack()



class TrainingPage(tk.Frame):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent)

        label = tk.Label(self, text="Starting Training")
        label.pack(pady=10,padx=10)

        button1 = customtkinter.CTkButton(self, text="Back",
                                command=lambda: controller.show_frame(RegistrationPage), fg_color="#6225E6")
        button1.pack()

        button2 = customtkinter.CTkButton(self, text="Start",
                                command=controller.select_ml_model, fg_color="#6225E6")
        button2.pack()