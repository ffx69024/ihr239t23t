@echo off
REM Run the decrypt script
python decrypt.py

REM Wait for user input
set /p mainmenuinput=Input Selection: 

REM You can add more logic here based on the user input
echo You selected: %mainmenuinput%