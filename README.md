# F21CN-F20CN-2022-23-CW2

Project for paired work on Computer Network Security's second coursework. The project should be forked by one pair member. It should only be accessible by the members of the pair and by the F21CN F20CN 2022-23 Lab-Helpers group (automatically members).

This application was developed on Windows Operating System, and requires changes to the different paths existing in the code.

This is an application created by Sasha and Salman for signature verification and signature recording. It is capable of creating certificates 
signed by CA, signing files with the new certificate created. Send the document, document signature and the corresponding x509 certificate over 
network anywhere in a secure encrypted way (AES-128). The application also has a separate application called Reciever Application which is used by 
others to receive your files. The application is also capable of verifying the signatures to a document and sign the verified document with your 
PGP private key. Finally one can verify the PGP signatures to a document.

To install these libraries on your system, run the following commands for each of the library.
- pip install cryptography
- pip install python-gnupg
- pip install pycryptodome
- pip install pyopenssl

-------------------------------------------------------- GNUPG PATH SETUP -----------------------------------------------------------------------
python-gnupg must be installed on the windows terminal. Once this is done GnuPG 1.4 Package must be installed locally into the system from the
internet "https://www.gnupg.org/download/". The directory of the file installed must be added to the environmental path so it can be accessed 
globally by the terminal. Since the home direcotory is also not set as default location in Windows, we must set the gnupghome globally as well.
Run the following code to set gnupghome directory.

	Python 3.11.0 (main, Oct 24 2022, 18:26:48) [MSC v.1933 64 bit (AMD64)] on win32
	Type "help", "copyright", "credits" or "license" for more information.
	>>> import gnupg
	>>> gnupg.__version__
	'2.0.2'
	>>> homedir=''
	>>> gpg = gnupg.GPG(homedir=homedir)
	>>> gpg = gnupg.GPG(gnupghome=homedir)

-------------------------------------------------- INITAL SETUP BEFORE RUNNING DOC VERIFIER ----------------------------------------------------------
Before running the application, please change the PGP path to your system's. Without this, the application will throw errors and not run
Modify line in python file 'support_ser.py' to the location of your gnupghome which will be 
gpg = gnupg.GPG(gnupghome='C:/Users/"username"/AppData/Roaming/gnupg')

------------------------------------------------ TO CREATE AN APPLICATION FROM THE SOURCE FILES -------------------------------------------------
Open the .spec files in both directories ('main_rec.spec' and 'main_ser.spec') and change the paths before /src/filename to that of the directory 
the folder is in.
Then open terminal in the folder 'Receiver_App' and run 'pyinstaller main_rec.spec' to create an application for the server side.
Then open terminal in the folder 'Server_App' and run 'pyinstaller main_ser.spec' in terminal to create an application for the document verification.

-------------------------------------------------- SENDING FILES VIA NETWORK --------------------------------------------------------------------
This is to inform you that now the certificates for client are loaded in automatically and there is no need to use the buttons to import the 
client certificate, client key and CA certificate. If you want to verify if handshake really occurs, you can use the buttons to import other 
certificates which will result in a handshake fail.

-------------------------------------------------- RUNNING THE FILE ON TERMINAL -----------------------------------------------------------------
Below are the instructions to run the application using terminal - 
To run the application on your system, goto Server_App and open a terminal there and run the python file named main.ser.py by running the command 
'python main_ser.py'. This should start a GUI.
When you need to send the files via a network, goto Receiver_App and launch the file main_ser.py from terminal by running 
'python main_rec.py'
