from tkinter import *
from tkinter.constants import E, W
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog


# This function is used for the logs generated in the GUI, we configure it such that by passing in a variable success=True we can set the color of logs to green
# and setting the variable fail=True we can set the color of logs to red. This is used to display warnings and success messages on the log.
def logData(data, success=False, fail=False):
    msg = format(data)
    logs.configure(state='normal')
    if(success):
        logs.insert(END, msg + '\n', 'success')
    elif(fail):
        logs.insert(END, msg + '\n', 'fail')
    else:
        logs.insert(END, msg + '\n')
    logs.configure(state='disabled')
    logs.yview(END)
    logs.tag_config('fail', foreground='red')
    logs.tag_config('success', foreground='green')

# Create a main instance for the GUI where all elements will be placed.
screen = Tk()
screen.title('Receive')
screen.geometry('900x280')


C = Canvas(screen, bg="blue", height=250, width=300)
filename = PhotoImage(file = ".\Images\leaves.png")
background_label = Label(screen, image=filename)
background_label.place(x=0, y=0, relwidth=1, relheight=1)
C.grid()

frame2 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1, height=200)
frame2.place(x=3,y=20)


Label(frame2, text="Public IP of TX",font=('Bahnschrift',10)).grid(row=1,column=0)
publicIPVal = StringVar()
publicIPLabel=Entry(frame2, textvariable=publicIPVal,font=('Bahnschrift',10)).grid(row=1,column=1)

Label(frame2, text='Port',font=('Bahnschrift',10)).grid(row=2, column=0)
portVal = StringVar()
portLabel = Entry(frame2, textvariable=portVal,font=('Bahnschrift',10)).grid(row=2, column=1)


# Selects the path from user and sets it to currentDirectory.
def getcurrentDirectory():
    currentDirectory.set(filedialog.askdirectory())
    logData("Location of saved signature files: "+currentDirectory.get())
def receiveDocuments():
    receiveDocuments(publicIPVal.get(), int(portVal.get()), currentDirectory.get())
    logData('Files received successfully!', success=True)


currentDirectory = StringVar(frame2)
loadClientCertificate = Button(frame2, text='Set saving directory', command=getcurrentDirectory, width=25,font=('Bahnschrift',10)).grid(row=3, column=0, columnspan=2)
loadClientKey = Button(frame2, text='Receive', command=receiveDocuments, width=25,font=('Bahnschrift',10)).grid(row=4, column=0, columnspan=2)


frame4 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame4.place(x=250,y=20)

Label(frame4, text="Logs", font=('Bahnschrift',18, 'bold')).grid(row=0,column=0)

logs = ScrolledText(frame4, state='disabled')
logs.configure(font='TkFixedFont', height=12, width=75)
logs.grid(row=1, column=0)

screen.mainloop()