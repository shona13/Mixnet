import string
import random
import gmpy2 as gmp

'''
    Author : Sonal Joshi
    Description : Mixnet server implementation using Elgamal cryptosystem
'''

# User creation
def users(n):
    # Creates a list of alphabets
    alpha = [''.join(i) for i in string.ascii_uppercase]
    # Senders
    source = [alpha[i] for i in range(n + 1)]
    # Receivers
    dest = [alpha[i] for i in range(n + 1, n + n + 2)]
    return source,dest


# Message generation for senders
def msg(users,n):
    all = string.digits
    # Length of message
    length = 7
    # Creates a list of messages
    messages = [int("".join(random.sample(all, length))) for i in range(n+1)]
    # Creates a dictionary with key & value as senders and messages
    u_msg = dict(zip(users,messages))
    return u_msg


# Key generation generic function of Elgamal
def key_gen(x):
    y = gmp.powmod(g, x, p)
    return y


# Receiver's public key function
def recv_pk(recv):
    PK = []
    Y = []
    random_state = gmp.random_state(hash(gmp.random_state()))
    for rec in recv:
        # Randomly generates x
        x = gmp.mpz_urandomb(random_state, gmp.mpz('8'))
        # Creates an object of key_gen() and returns y
        y = key_gen(x)
        # Creates a list of receivers public key parameter y
        Y.append(y)
        # Generates a list of public key (y,g,p) for each receiver
        PK.append((y,g,p))
    return Y,PK


# Generic encryption function of Elgamal
def encrypt(r,m,y):
    # Ciphertext c1 & c2 generation
    c1 = gmp.powmod(g,r,p)
    c2 = gmp.mod(m*(gmp.powmod(y,r,p)),p)
    # Ciphertext C = (c1,c2)
    C = (c1, c2)
    return C


# Encryption function for messages using receiver public key
def enc_recv_pk(msgs,Y):
    C1 = []
    i = 0
    # Assigns only the values from the dictionary & makes it a list
    m = list(msgs.values())
    random_state = gmp.random_state(hash(gmp.random_state()))
    for y in Y:
        # Generates random r each time in loop
        r = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
        # Appends it to the list of all encrypted msgs
        C1.append(encrypt(r,m[i],y))
        i += 1
    return C1


# Identity creation function for each user in the system
def identity(sen,rec,a):
    iden = [int(i) for i in range(a+2)]
    # total = sen + rec
    # Returns a dictionary of total users with it's identity
    id_dict = dict(zip(sen+rec,iden))
    return id_dict


# Mixnet key generation function
def mixnet_keygen():
    random_state = gmp.random_state(hash(gmp.random_state()))
    # Randomly generates x
    x = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
    y = key_gen(x)
    return x,y


# Encrypts ciphertexts using cipher + identity of user usin mixnet PK
def enc_server_pk(enc_msgs, y, iden):
    random_state = gmp.random_state(hash(gmp.random_state()))
    i = 0
    C1_id = []
    C2_id = []
    # Extracts values from identity dictionary and converts it into list
    id_list = list(iden.values())
    r = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
    for m in enc_msgs:
        # Tuple unpacking
        c1,c2 = m
        # Appends c1 to C1 list & c2 to C2 list
        C1_id.append(encrypt(r,c1 + id_list[i],y))
        C2_id.append(encrypt(r,c2 + id_list[i],y))
        i += 1
    # Joins C1 & C2 lists
    last = list(zip(C1_id,C2_id))
    return last


# Function to shuffle all he ciphers
def mixnet(ciphers):
    # Creating a new list to keep origina intact
    shuffled_ciphers = ciphers.copy()
    # Shuffling the new list randomly
    random.shuffle(shuffled_ciphers)
    return shuffled_ciphers


# Decryts the C = (c1,c2) using server's private/secret key
def decrypt(x,shc):
    dec_msg = []
    for i in range(n+1):
        for c in shc[i]:
            c1,c2 = c
            # - x is for inverse
            t = gmp.powmod(c1,-x,p)
            # Calculates decrypted message & apends it to the list
            dec_msg.append(gmp.mod(c2*t,p))
    return dec_msg


if __name__=='__main__':
    ### Global p,g values make it easier for each function to use it without needing to pass it as parameters ###
    global p,g
    # Prime p (given)
    p = gmp.mpz(5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807)
    g = gmp.mpz(2)

    ### Taking user input ###
    user_n = int(input("Enter the value of users in the system n > 15:  "))
    n = gmp.mpz(user_n / 2)

    '''
        Calling the functions and creating objects for each function
    '''
    ### Creating objects of each function/method ###
    senders,recv = users(n)
    dict_msgs = msg(senders, n)
    x, ys = mixnet_keygen()
    y, pk = recv_pk(recv)
    dict_pk = dict(zip(recv,pk))
    C = enc_recv_pk(dict_msgs,y)
    iden = identity(senders,recv,n)
    mix = enc_server_pk(C,ys,iden)
    shuf_ciphers= mixnet(mix)
    dec_msgs = decrypt(x,shuf_ciphers)


    '''
        Printing values on terminal    
    '''

    ### Printing the users ###
    print("-" * 20, "Users", "-" * 20)
    print("Senders: ",senders)
    print("Recivers:",recv)

    ### Printing the messages ###
    print("-" * 20, "Messages (Randomly generated)", "-" * 20)
    print("Dict msg:", dict_msgs)

    ### Encryption process ###
    print("-" * 20, "Encryption", "-" * 20)
    print("Encryption of messages with destination PK: ",C)
    print("Encryption of Cipher + id using mixnet server PK :",mix)

    ### Shuffling the cipher texts inside the mixnet ###
    print("-" * 20, "Shuffling", "-" * 20)
    print("Shuffled ciphertexts in the mixnet server: ",shuf_ciphers)

    ### Decryption process ###
    print("-" * 20, "Decryption ", "-" * 20)
    print("Decryption of cipher + id using mixnet's secret key",dec_msgs)
