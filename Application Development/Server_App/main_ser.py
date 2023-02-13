from logging import log
from multiprocessing.connection import Client
import ssl
from tkinter import *
from tkinter import ttk
from tkinter.constants import E, LEFT, W
from tkinter.filedialog import askopenfilename
from tkinter.scrolledtext import ScrolledText
import tkinter.font as font
from tkinter import filedialog
from turtle import width, window_width
import support_ser
import PIL.Image
from PIL import Image, ImageTk



# This is the GUI and is divided into 5 frames, each frame responsible for one part of the the code. Before the start of each frame, a comment has been added to indicate
# what that part of the application it runs.
screen = Tk()
screen.title('Document Verification')
screen.geometry('1500x670')
screen.configure(bg='blue')
screen.title("Server")

C = Canvas(screen, bg="blue", height=250, width=300)
filename = PhotoImage(file = ".\Images\leaves.png")
background_label = Label(screen, image=filename)
background_label.place(x=0, y=0, relwidth=1, relheight=1)
C.grid()

currentDirectory = StringVar()
PKCS12Path = StringVar()
CACertificatePath = StringVar()
documentToSignPath = StringVar()
otherPairCertificatePath = StringVar()
otherPairSignaturePath = StringVar()
otherPairDocumentPath = StringVar()

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

def getPKCS12():
    PKCS12Path.set(askopenfilename())
    logData("The location of PKCS12 is set as: "+PKCS12Path.get())

def getDocumentToSign():
    documentToSignPath.set(askopenfilename())
    logData("The location of document to sign is set as: "+documentToSignPath.get())
def setWorkingDirectory():
    currentDirectory.set(filedialog.askdirectory())
    logData("Location of saved signature files: "+currentDirectory.get())
    logData('Creating empty CRL file, without CRL, the document will not proceed with verification!')
    createCRLSave(dummy=False)
    logData('Warning - Do not delete or move any files from this directory unless the logs sow you in green that you can!!', fail=True)
def generatex509Signature():
    country = countryVal.get()
    state = stateVal.get()
    city = cityVal.get()
    org = orgVal.get()
    unit = unitVal.get()
    cn = cnVal.get()
    email = emaiLVal.get()
    logData("Signing the certificate with below details")
    logData("Country: "+country)
    logData("State: "+state)
    logData("City: "+city)
    logData("Organisation: "+org)
    logData("Unit: "+unit)
    logData("Common Name: "+cn)
    logData("Email: "+email)
    support_ser.part3(PKCS12Path.get(), pkcsPassword.get(), country, state, city, org, unit, cn, email, documentToSignPath.get(), currentDirectory.get())

#-------------------------------------------------------- FRAME 1 - LOAD EVERYTHING, CREATE CSR AND SIGN DOC ------------------------------------------------------------------#

frame1 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame1.place(x=30,y=10)

Label(frame1, text='Set on Startup', font=('Bahnschrift',18, 'bold')).grid(row=0, column=0, columnspan=2)
Label(frame1, text="Enter PKCS12 password",font=('Bahnschrift',10)).grid(row=1, column=0)
pkcsPassword = StringVar(frame1)
passwordLabel = Entry(frame1, show='*', textvariable=pkcsPassword,font=('Bahnschrift',10)).grid(row=1, column=1, sticky=W)
x509CAPrivateKey = Button(frame1, text='Load PKCS12 contaning CA', command=getPKCS12,font=('Bahnschrift',10), width=25).grid(row=2, column=0, columnspan=2)
getWorkingDirectory = Button(frame1, text='Set directory for saving files', command=setWorkingDirectory,font=('Bahnschrift',10),width=25).grid(row=3, column=0, columnspan=2)
Label(frame1, text="Sign document using x509", font=('Bahnschrift',18, 'bold')).grid(row=4,column=0, columnspan=2)
loadDocumentToSign = Button(frame1, text='Load the document to sign', command=getDocumentToSign,font=('Bahnschrift',10),width=25).grid(row=5, column=0, columnspan=2)

Label(frame1, text="Country", justify=LEFT,font=('Bahnschrift',10)).grid(row=6,column=0, sticky=W)
Label(frame1, text="State", justify=LEFT,font=('Bahnschrift',10)).grid(row=7,column=0, sticky=W)
Label(frame1, text="City", justify=LEFT,font=('Bahnschrift',10)).grid(row=8,column=0, sticky=W)
Label(frame1, text="Organization", justify=LEFT,font=('Bahnschrift',10)).grid(row=9,column=0, sticky=W)
Label(frame1, text="Unit", justify=LEFT,font=('Bahnschrift',10)).grid(row=10,column=0, sticky=W)
Label(frame1, text="Common Name", justify=LEFT,font=('Bahnschrift',10)).grid(row=11,column=0, sticky=W)
Label(frame1, text="Email", justify=LEFT,font=('Bahnschrift',10)).grid(row=12,column=0, sticky=W)

countryVal = StringVar(frame1, value='AE')
stateVal = StringVar(frame1, value='Dubai')
cityVal = StringVar(frame1, value='Dubai')
orgVal = StringVar(frame1, value='HW')
unitVal = StringVar(frame1, 'MACS')
cnVal = StringVar(frame1, value='document')
emaiLVal=StringVar(frame1, 'docsig@macs.com')

countryLabel=Entry(frame1, textvariable=countryVal,font=('Bahnschrift',10)).grid(row=6,column=1, sticky=W)
stateLabel=Entry(frame1, textvariable=stateVal,font=('Bahnschrift',10)).grid(row=7,column=1, sticky=W)
cityLabel=Entry(frame1, textvariable=cityVal,font=('Bahnschrift',10)).grid(row=8,column=1, sticky=W)
orgLabel=Entry(frame1, textvariable=orgVal,font=('Bahnschrift',10)).grid(row=9,column=1, sticky=W)
unitLabel=Entry(frame1, textvariable=unitVal,font=('Bahnschrift',10)).grid(row=10,column=1, sticky=W)
cnLabel=Entry(frame1, textvariable=cnVal,font=('Bahnschrift',10)).grid(row=11,column=1, sticky=W)
emailLabel=Entry(frame1, textvariable=emaiLVal,font=('Bahnschrift',10)).grid(row=12,column=1, sticky=W)

finalButtonFont = font.Font(family='Bahnschrift', size=11, weight='bold')
createSignedDocument = Button(frame1, text='Generate Document Signature', font=finalButtonFont, command=generatex509Signature, height=2).grid(row=13, column=0, columnspan=2)

#-------------------------------------------------------- FRAME 2 - SEND FILES VIA NETWORK WITH TLS/AES ENCRYPTION ------------------------------------------------------------------#
frame2 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1, height=200)
frame2.place(x=390,y=10)


Label(frame2, text="Send files via network", font=('Bahnschrift',18, 'bold')).grid(row=0,column=0, columnspan=2)
Label(frame2, text="Public IP of RX",font=('Bahnschrift',10)).grid(row=1,column=0)
publicIPVal = StringVar()
publicIPLabel=Entry(frame2, textvariable=publicIPVal,font=('Bahnschrift',10)).grid(row=1,column=1)

Label(frame2, text='Port',font=('Bahnschrift',10)).grid(row=2, column=0)
portVal = StringVar()
portLabel = Entry(frame2, textvariable=portVal,font=('Bahnschrift',10)).grid(row=2, column=1)
clientCertificatePath = StringVar()
clientKeyPath = StringVar()
caCertificatePath = StringVar()

def getClientCertificate():
    clientCertificatePath.set(askopenfilename())
    logData('The location of client certificate is set as: '+clientCertificatePath.get())
def getClientKey():
    clientKeyPath.set(askopenfilename())
    logData('The location of client key is set as: '+clientKeyPath.get())
def getCACertificate():
    caCertificatePath.set(askopenfilename())
    logData('The location of CA certificate is set as: '+caCertificatePath.get())
def sendFilesTo():
    if(currentDirectory.get()==''):
        logData('Directory to get files for sending not set!', fail=True)
        logData('Select directory containing the files to send')
        currentDirectory.set(filedialog.askdirectory())
    status = support_ser.client.init(publicIPVal.get(), int(portVal.get()), clientCertificatePath.get(), clientKeyPath.get(), caCertificatePath.get(), currentDirectory.get())
    if(status=='sent'):
        logData('All files sent.', success=True)
        logData('You can now safely delete or move the files from the working directory', success=True)
    elif(status==ssl.SSLError):
        logData('TLS Handshake FAILED. Certificate mismatch.'+str(status), fail=True)
    elif(status==ConnectionRefusedError):
        logData('Connection refused'+str(status), fail=True)
        logData('Please ensure the server is running or try changing ports', fail=True)
    else:
        logData('There was an error in transmission, please retry.', fail=True)

loadClientCertificate = Button(frame2, text='Select client certificate', command=getClientCertificate, width=25,font=('Bahnschrift',10)).grid(row=3, column=0, columnspan=2)
loadClientKey = Button(frame2, text='Select client key', command=getClientKey, width=25,font=('Bahnschrift',10)).grid(row=4, column=0, columnspan=2)
loadCACertificate = Button(frame2, text='Select CA certificate', command=getCACertificate, width=25,font=('Bahnschrift',10)).grid(row=5, column=0, columnspan=2)
sendFilesOnNetwork = Button(frame2, text='Send documents over network', font=finalButtonFont, command=sendFilesTo, height=2).grid(row=6, column=0, columnspan=2)
#-------------------------------------------------------- FRAME 3 - VERIFY OTHER PAIR'S DOC AND SIGN DOC ------------------------------------------------------------------#
frame3 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame3.place(x=700,y=10)

def getPairx509Certificate():
    otherPairCertificatePath.set(askopenfilename())
    logData("The location of other PAIR x509 Ceritificate is set as: "+otherPairCertificatePath.get())
def getPairDocumentSignature():
    otherPairSignaturePath.set(askopenfilename())
    logData("The location of other PAIR signature is set as: "+otherPairSignaturePath.get())
def getPairDocument():
    otherPairDocumentPath.set(askopenfilename())
    logData("The location of PAIR document is set as: "+otherPairDocumentPath.get())
def getPairDocumentVerification():
    if(crlPath.get()==''):
        logData('CRL file not loaded, please load it in the open window.', fail=True)
        crlPath.set(askopenfilename())
        logData('CRL file loaded from: '+crlPath.get())
    status = Client.x509_verify_file_sign_PGP(crlPath.get(), PKCS12Path.get(), pkcsPassword.get(), otherPairCertificatePath.get(), otherPairSignaturePath.get(), otherPairDocumentPath.get(), currentDirectory.get(), pgpPrivateKeyPasswordVal.get(), pgpPrivateKeyPassword1Val.get())
    pgpPrivateKeyPasswordVal.set('')
    pgpPrivateKeyPassword1Val.set('')

    if(status=='pair doc not verified'):
        logData("File from other could not be verified. Not signing their document!", fail=True)
    elif(status=='crl failed'):
        logData('Used Certificate from {} is revoked. Please try with a valid certificate'.format(otherPairCertificatePath.get()), fail=True)
    elif(status=='wrongh'):
        logData('Please enter the correct PGP password for Salman', fail=True)
    elif(status=='wrongs'):
        logData('Please enter the correct PGP password for Sasha', fail=True)
    else:
        logData('Files verified and signed with our PGP.', success=True)
        logData('The PGP signed files signed by us are stored in \n {}'.format(currentDirectory.get()))
def loadCRL():
    crlPath.set(askopenfilename())
    logData('CRL file read in from: '+crlPath.get())

Label(frame3, text="Document verification and signing", font=('Bahnschrift',18, 'bold')).grid(row=0,column=0, columnspan=2)
crlPath = StringVar()
crl = Button(frame3, text='Load CRL file', command=loadCRL,font=('Bahnschrift',10), width=30).grid(row=1, column=0, columnspan=2)
pairx509Certificate = Button(frame3, text='Load pairs x509 Certificate', command=getPairx509Certificate, font=('Bahnschrift',10), width=30).grid(row=2, column=0, columnspan=2)
pairDocumentSignature = Button(frame3, text='Load the signature of the document', command=getPairDocumentSignature, font=('Bahnschrift',10), width=30).grid(row=3, column=0, columnspan=2)
pairDocument = Button(frame3, text='Load the document to verify', command=getPairDocument, font=('Bahnschrift',10),width=30).grid(row=4, column=0, columnspan=2)

pgpPrivateKeyPasswordVal = StringVar(frame3)
Label(frame3, text='Enter password PGP Salman', justify=LEFT,font=('Bahnschrift',10)).grid(row=5, column=0)
pgpPrivateKeyPasswordLabel = Entry(frame3, show='*', textvariable=pgpPrivateKeyPasswordVal,font=('Bahnschrift',10)).grid(row=5, column=1)

pgpPrivateKeyPassword1Val = StringVar(frame3)
Label(frame3, text='Enter password PGP Sasha', justify=LEFT,font=('Bahnschrift',10)).grid(row=6, column=0)
pgpPrivateKeyPassword1Label = Entry(frame3, show='*', textvariable=pgpPrivateKeyPassword1Val,font=('Bahnschrift',10)).grid(row=6, column=1)

verifyPairDocument = Button(frame3, text='Verify & Sign the document', font=finalButtonFont, command=getPairDocumentVerification, width=25, height=2).grid(row=7, column=0, columnspan=2)
#-------------------------------------------------------- FRAME 4 - PRINT LOGS FROM CURRENT USER OPERATIONS ------------------------------------------------------------------#
frame4 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame4.place(x=30,y=420)

Label(frame4, text="Logs", font=('Bahnschrift',18, 'bold')).grid(row=0,column=0)

logs = ScrolledText(frame4, state='disabled')
logs.configure(font='TkFixedFont', height=12, width=175)
logs.grid(row=1, column=0)

#--------------------------------------------------------- FRAME 3 - CRL LISTS -------------------------------------------------------------------------------
frame6 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame6.place(x=1210,y=230)
Label(frame6, text="CRL", font=('Bahnschrift',18, 'bold')).grid(row=0,column=3)

def getCertificateToRevoke():
    certificateToRevokePath.set(askopenfilename())
    logData('Certificate to revoke selected at: '+certificateToRevokePath.get())
def createCRLSave(dummy=True):
    if(currentDirectory.get()==''):
        logData('Current directory not selected, please select in the window open now', fail=True)
        currentDirectory.set(filedialog.askdirectory())
        logData('Current directory set as: '+currentDirectory.get())
    if(PKCS12Path.get()==''):
        logData('PKCS12 path not set, please set it in the window open now', fail=True)
        PKCS12Path.set(askopenfilename())
        logData('PKCS12 path set as: '+ PKCS12Path.get())
    if(pkcsPassword.get==''):
        logData('Please enter PKCS12 password before creating CRL and retry', fail=True)
    else:
        support_ser.createCRL(PKCS12Path.get(), pkcsPassword.get(), certificateToRevokePath.get(), currentDirectory.get(), dummy)
        logData('CRL Created succesfully at location: '+currentDirectory.get(), success=True)

certificateToRevokePath = StringVar()
certificateToRevoke = Button(frame6, text='Load certificate to revoke', command=getCertificateToRevoke,font=('Bahnschrift',10), width=25).grid(row=1, column=3, columnspan=2)
createCRLList = Button(frame6, text='Create CRL', command=createCRLSave,font=('Bahnschrift',10),width=25).grid(row=2, column=3, columnspan=2)

#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------ FRAME 5 PGP RECEIVE VERIFICATION -----------------------------------------------------------------
frame5 = Frame(screen, padx=5, pady=5, highlightbackground='black', highlightthickness=1)
frame5.place(x=1150,y=10)

Label(frame5, text="Verify received files - PGP", font=('Bahnschrift',18, 'bold')).grid(row=0,column=0, columnspan=2)
def getSignature1Path():
    pgpSignature1Path.set(askopenfilename())
    logData('PGP signature 1 path set as: '+pgpSignature1Path.get())
def getSignature2Path():
    pgpSignature2Path.set(askopenfilename())
    logData('PGP signature 2 path set as: '+pgpSignature2Path.get())

def verifyPGPSignatures():
    if(returnedDocumentPath.get()==''):
        logData('Document to verify not loaded, please load it now in the current window')
        returnedDocumentPath.set(askopenfilename())
    status = Client.verify_file_pgp(pgpSignature1Path.get(), returnedDocumentPath.get())
    if(status=='no'):
        logData('Invalid Signature for first fileloaded', fail=True)
    elif(status=='pgp_verified'):
        logData('First signature verified', success=True)
    else:
        logData('Unexpected error')

    status1 = Client.verify_file_pgp(pgpSignature2Path.get(), returnedDocumentPath.get())
    if(status1=='no'):
        logData('Invalid Signature for second fileloaded', fail=True)
    elif(status1=='pgp_verified'):
        logData('Second signature verified', success=True)
    else:
        logData('Unexpected error')
def getReturnedDocument():
    returnedDocumentPath.set(askopenfilename())

returnedDocumentPath = StringVar()    
pgpSignature1Path = StringVar()
signature1 = Button(frame5, text='Load PGP signature 1', command=getSignature1Path,font=('Bahnschrift',10), width=20).grid(row=1, column=0, columnspan=2)
pgpSignature2Path = StringVar()
signature1 = Button(frame5, text='Load PGP signature 2', command=getSignature2Path,font=('Bahnschrift',10), width=20).grid(row=2, column=0, columnspan=2)
verifySignature = Button(frame5, text='Verify Signatures', command=verifyPGPSignatures,font=('Bahnschrift',10), width=20).grid(row=3, column=0, columnspan=2)
loadDocument = Button(frame5, text='Load document to verify', command=getReturnedDocument,font=('Bahnschrift',10),width=20).grid(row=4, column=0, columnspan=2)



screen.mainloop()
