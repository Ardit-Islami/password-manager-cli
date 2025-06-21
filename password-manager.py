def main():
    pass

class PasswordManager:

    def __init__(self):
        self._salt = os.urandom(16) # data type: bytes
        self._iterationAmount = 100000
        # Data for the file:
        self._MasterData = {}
        # Initialise Empty Password Vault,
        self._vault = {}
        # In session vault key:
        self._sessionKey = ''
        self._signedOn = False

    # Creating Master Password and using KDF for secure handling of Master Key.
    def Vault_Initialiser(self):
        # Master Password String,
        master_key_generation = getpass.getpass("Create the Master Password for your Password vault: ")
        # Generate KDF,
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self._salt, iterations=self._iterationAmount)
        # Create Key,
        self._sessionKey = kdf.derive(master_key_generation.encode()) # We turn the string into bytes

        # ======= PREPARING FOR DATA STORAGE =======
        salt_string = base64.b64encode(self._salt).decode('utf-8') # Required for json dump/load as it doesn't work with bytes
    
        # Creating an encrypted Vault File via Fernet
        b64_key = base64.urlsafe_b64encode(self._sessionKey) # Found out that Fernet only takes 32 url-safe base64-encoded bytes
        f = Fernet(b64_key) # symmetric authenticated cryptography using our "Derived Key"

        # Using json module to turn vault dictionary into string
        vault_string = json.dumps(self._vault)
        # As fernet only works with bytes, i.e. b"password" -> we encode:
        vault_bytes = vault_string.encode('utf-8')
        # Now we can encrypt:
        vault_encrypted = f.encrypt(vault_bytes)
        # Now to b64 for json dump/load:
        vault_b64 = base64.b64encode(vault_encrypted).decode('utf-8') # Creates a base64encoded representation -> then we decode it into a string.
        
        # Create the file to store Salt and Iteration Amount
        self._MasterData = {"salt_setting": salt_string, "iteration_setting": self._iterationAmount, "secure_vault": vault_b64}
        with open('test.txt', "w") as t:
            t.write(json.dumps(self._MasterData))

        self._signedOn = True

    # Creating sign-on ability
    def Sign_On(self):
        with open("test.txt", "r") as t:
            self._MasterData = json.load(t)   
        
        # Undo the steps of Vault initialiser, to gain access to Vault details:
        vault_decoded = base64.b64decode(self._MasterData.get('secure_vault'))

        # === Undo Encryption ===
        # We want to allow for multiple login attempts,
        attempts = 0
        max_attempts = 3

        while attempts < max_attempts+1:
            try:
                user_input = getpass.getpass("Input Password: ")
                new_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt= base64.b64decode(self._MasterData.get('salt_setting')), iterations = self._MasterData.get('iteration_setting'))

                # First attempt derived key check:
                self._sessionKey = new_kdf.derive(user_input.encode())
                b64_rederived_key = base64.urlsafe_b64encode(self._sessionKey) # For Fernet check.
                f = Fernet(b64_rederived_key)

                vault_decrypted = f.decrypt(vault_decoded)

                vault_toString = vault_decrypted.decode('utf-8')                    # Change back from bytes to string
                self._vault = json.loads(vault_toString)                            # Change from json module string to original dictionary
                self._signedOn = True
                break
            except InvalidToken:                                                    # as per https://cryptography.io/en/latest/fernet/#cryptography.fernet.InvalidToken
                if attempts < max_attempts:
                    attempts += 1
                    print("Incorrect Password, Try Again.")
                else:
                    self._signedOn = False
                    print("Maximum attempts Reached. Login Denied.")
                    break
            except FileNotFoundError:
                print("Please ensure the Vault Exists")
                break
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

    # View existing vault,
    def view_password(self):
        print(self._vault)
    
    # Add new password,
    def add_password(self):
        new_key = ''
        new_password = ''

        while not new_key or not new_password:
            print("Please ensure you don't leave empty values.")
            new_key = input('What Email/Account do you wish to store a password for: ').lower()
            new_password = input('What will be the new password: ')
        
        if new_key in self._vault:
            print("This key already exists")
        else:
            self._vault[new_key] = new_password
            print("New Password has been added.")
    
    # Remove existing password,
    def remove_password(self):
        print(self._vault)
        account_selector = ''

        while not account_selector:
            account_selector = input('Which Account do you wish to select to remove from the Vault? ')
        
        if account_selector in self._vault:
            del self._vault[account_selector]
        else:
            print('Account not Found.')
        
    # Update existing password,
    def update_password(self):
        print(self._vault)
        account_selector = ''
        updated_password = ''

        while not account_selector:
            account_selector = input('Which Account do you wish to select to update the password of? ')
        while not updated_password:
            updated_password = input('Create your new password: ')
        
        if account_selector in self._vault:
            self._vault[account_selector] = updated_password
        else:
            print('Account not Found. Use "Add Password".')
    
    # Sign off and save existing vault back to file
    def sign_off(self):
        # ======= PREPARING FOR DATA STORAGE =======
        b64_rederived_key = base64.urlsafe_b64encode(self._sessionKey)
        f = Fernet(b64_rederived_key)

        vault_string = json.dumps(self._vault)
        vault_bytes = vault_string.encode('utf-8')
        vault_encrypted = f.encrypt(vault_bytes)
        vault_b64 = base64.b64encode(vault_encrypted).decode('utf-8')
        
        # Amending our _MasterData
        self._MasterData['secure_vault'] = vault_b64
        
        with open('test.txt', "w") as t:
            t.write(json.dumps(self._MasterData))
        
        self._signedOn = False

if __name__ == "__main__":
    import getpass
    import os
    from cryptography.hazmat.primitives import hashes                       # as per cryptography.io
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC        # as per cryptography.io
    from cryptography.fernet import Fernet                                  # as per cryptography.io
    from cryptography.fernet import InvalidToken                            # for exception management
    import json                                                             # Working with dicts
    import base64                                                           # encoding/decoding bytes
    
    # Initialise our Class instance:
    Manager_Instance = PasswordManager()
   
    # Start-up - i.e. either first time launch or new login:
    if os.path.exists('test.txt'):
        Manager_Instance.Sign_On()
    else:
        Manager_Instance.Vault_Initialiser()
    
    # Dictionary of Functions user can use:
    command_centre = {'view': Manager_Instance.view_password, 
                      'add password': Manager_Instance.add_password, 
                      'remove password': Manager_Instance.remove_password,
                      'update password': Manager_Instance.update_password,
                      'sign off': Manager_Instance.sign_off}

    # Interactive Command Centre for the user to interact with Vault.
    while Manager_Instance._signedOn is True:
        try:
            user_command = input('''
                            -------------------------------------------------------------------
                            What do you wish to do? 
                            View | Add Password | Remove Password | Update Password | Sign Off
                            -------------------------------------------------------------------
                            -> ''').lower()
            
            command = command_centre.get(user_command)
            if command == command_centre.get('sign off'):
                print('You will now be signed off')
                command()
            else:
                command()
        
        except TypeError:
            print('''You have not inputted a valid command. Please select from:
                                                                                View | Add Password | Remove Password | Update Password | Sign Off
                  ''')
    

 




