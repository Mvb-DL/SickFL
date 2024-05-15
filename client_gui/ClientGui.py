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

        self.config(bg="black")

        label = tk.Label(self, text="Registration")
        label.pack(pady=10,padx=10)

        clientname_label = customtkinter.CTkLabel(self, text="Client Name")
        clientname_label.pack()
        clientname_entry = customtkinter.CTkEntry(self, placeholder_text="Client Name", fg_color="#fff")
        clientname_entry.pack()

        password_label = customtkinter.CTkLabel(self, text="Client Password")
        password_label.pack()
        password_entry = customtkinter.CTkEntry(self, placeholder_text="Password", fg_color="#fff")
        password_entry.pack()

        #email
        email_label = customtkinter.CTkLabel(self, text="Client E-Mail")
        email_label.pack()
  
        email_entry = customtkinter.CTkEntry(self, placeholder_text="Email", fg_color="#fff")
        email_entry.pack()

        button = customtkinter.CTkButton(self, text="Register",
                                command=controller.send_register_data, fg_color="#6225E6")

        button.pack()
        


class ModelSelectPage(tk.Frame):

    def __init__(self, parent, controller):

        tk.Frame.__init__(self, parent)

        label = tk.Label(self, text="Model Selection")
        label.pack(pady=10,padx=10)


        button1 = customtkinter.CTkButton(self, text="Back",
                                command=lambda: controller.show_frame(RegistrationPage), fg_color="#6225E6")
        button1.pack()

        button2 = customtkinter.CTkButton(self, text="Start",
                                command=controller.select_ml_model, fg_color="#6225E6")

        
        button2.pack()


class ModelSelectPage(tk.Frame):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent)

        label = tk.Label(self, text="Model Selection")
        label.pack(pady=10,padx=10)

        button1 = customtkinter.CTkButton(self, text="Back",
                                command=lambda: controller.show_frame(RegistrationPage), fg_color="#6225E6")
        button1.pack()

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