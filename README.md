# Setup the tool
Edit the webserver.py script and set the local IP of the computer running the script.
The IP should be in the same subnet as the coffee machine.

# Running the script
Execute the webserver.py script
During the first run, you'll need to authenticate using your delonghi's account.
- Follow the URL displayed: https://fidm.eu1.gigya.com/oidc/op/v1.0/3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2/authorize?client_id=1S8q1WJEs-emOB43Z0-66WnL&response_type=code&redirect_uri=https://google.it&scope=openid%20email%20profile%20UID%20coffee&nonce=1707250274134
- At the end of the authentication process, you should be redirected to a google.it URL containing your authentication code. Copy the URL and paste it into the script
- The authentication process will continue and should create 2 files: token.txt (ayla network auth) and keys.json (local connection encryption keys). Those files will be used to connect automatically next time you run the script

# Usage
Open the URL: http://127.0.0.1:10280/index.html
When you press one of the buttons, the python will try to send an encrypted query to the coffee machine.
If the query fails, the coffee machine sends a signal to initialize a new encrypted connection (/local_lan/key_exchange.json)
The return field should display the negociated AES keys (in case you want to sniff the conversation and decrypt it yourself)
In that case, you'll need to press the buttons another time to send it.

# Feedback window
The feedback window will return any decoded info received from the coffee machine:
- Turn On doesn't return anything
- Status will return the value of d302_monitor property (base64 encoded binary)
- Bean info will return the value of d260_beansystem_sync_par (base64 encoded binary)
- Serial will return the value of d270_serialnumber (base64 encoded binary + text)
- Each time a coffee cup is made, the machine send a d260_beansystem_sync_par that is also displayed

All signal received will be logged in the log.txt file in order to help us understand the protocol.
