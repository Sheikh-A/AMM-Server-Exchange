#!/usr/bin/env python
# coding: utf-8

# In[10]:


#pip install progressbar
from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from web3 import Web3
import time

from algosdk import mnemonic
from algosdk.v2client import indexer


# In[2]:


# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """


# In[3]:


""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    #Add Session
    g.session.add(log(message = msg))
    #Add Commit
    g.session.commit()
    
    return

def valid_signature(payload,sig):
    result_valid_signature = False
    platform = payload['platform']

    pk = payload['pk']
    sk = sig
    
    message = json.dumps(payload)
    
    if platform == "Algorand":
        result_valid_signature = algosdk.util.verify_bytes(message.encode('utf-8'),sk,pk)
        if(result_valid_signature):
            result_valid_signature = True
    
    elif platform == "Ethereum":
        eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
        recovered_pk = eth_account.Account.recover_message(eth_encoded_msg,signature=sk)
        if(recovered_pk == pk):
            result_valid_signature = True
    else:
        print("INVALID CHECK")
    #Return Result    
    return jsonify(result_valid_signature)

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 

    mnemonic_secret = 'chuckle welcome exchange bless pink segment brand patrol salon aerobic other will present banana bachelor dream almost noble melt alien enter excess during ability trouble'
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
    print(acct)
    print(mnemonic_secret)


    # TODO: Generate or read (using the mnemonic secret) 
    mnemonic_secret = "song funny orchard upon glide burden section cherry glance nice chef drift"
    
    
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_secretkey = acct._private_key.hex()
    eth_pk = acct._address
    
    return eth_secretkey, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 

    order_obj = Order(receiver_pk=order['receiver_pk'],\
                      sell_currency=order['sell_currency'],\
                      buy_currency=order['buy_currency'],\
                      buy_amount=order['buy_amount'],\
                      sell_amount=order['sell_amount'] )
    g.session.add(order_obj)
    g.session.commit()

    matched_order = g.session.query(Order).filter(Order.filled==None,\
                                                  Order.buy_currency == order_obj.sell_currency,\
                                                  Order.sell_currency == order_obj.buy_currency,\
                                                  Order.sell_amount/Order.buy_amount >= order_obj.buy_amount/order_obj.sell_amount).first()
    
    #3. if a match is found
    if matched_order != None:
        matched_order.filled = datetime.now()
        order_obj.filled = matched_order.filled
        
        matched_order.counterparty_id = order_obj.id
        order_obj.counterparty_id = matched_order.id 
        
        if order_obj.buy_amount > matched_order.sell_amount:
                new_order = Order(receiver_pk = order_obj.receiver_pk,\
                                  buy_currency = order_obj.buy_currency, sell_currency = order_obj.sell_currency,\
                                  buy_amount = order_obj.buy_amount - matched_order.sell_amount,\
                                  sell_amount = (order_obj.buy_amount - matched_order.sell_amount)* order_obj.sell_amount / order_obj.buy_amount,\
                                  creator_id = order_obj.id)
                #print("partially filled, new_order.buy_amount > matched_order.sell amount, creator_id =", new_order.creator_id)
                #txes.append(order_obj.id)
                tx_obj = TX( platform = order_obj.sell_currency, receiver_pk = order_obj.receiver_pk, order_id = order_obj.id, tx_id = order_obj.tx_id)
                txes.append(tx_obj)
                g.session.add(tx_obj)
                g.session.add(new_order)
                g.session.commit()
                  
        if matched_order.buy_amount > order_obj.sell_amount:
                new_order = Order(receiver_pk = matched_order.receiver_pk,                                   buy_currency =matched_order.buy_currency, sell_currency = matched_order.sell_currency,                                   buy_amount = matched_order.buy_amount - order_obj.sell_amount,                                   sell_amount= (matched_order.buy_amount - order_obj.sell_amount) * matched_order.sell_amount / matched_order.buy_amount,                                  creator_id = matched_order.id)
                #print("partially filled, matched_order.buy_amount>new_order.sell_amount, creator_id =", new_order.creator_id)
                #txes.append(order_obj.id)
                tx_obj = TX( platform = order_obj.sell_currency, receiver_pk = order_obj.receiver_pk, order_id = order_obj.id, tx_id = order_obj.tx_id)
                txes.append(tx_obj)
                g.session.add(tx_obj)
                g.session.add(new_order)
                g.session.commit()
                
        if matched_order.buy_amount == order_obj.sell_amount:
                tx_obj = TX( platform = order_obj.sell_currency, receiver_pk = order_obj.receiver_pk, order_id = order_obj.id, tx_id = order_obj.tx_id)
                txes.append(tx_obj)
                g.session.add(tx_obj)
                g.session.commit()            
                
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
        if(order['sell_currency'] == "Ethereum"):
                w3 = connect_to_eth()
                tx = w3.eth.get_transaction(order['tx_id'])
                if(tx.value != order['sell_amount']):
                    log_message(order)
                    return jsonify( False )
        if(order['sell_currency'] == "Algorand"):
            acl = connect_to_algo(connection_type='indexer')
            time.sleep(3)
            tx = acl.search_transactions(txid = order['tx_id'])
        if(tx.value !=order['sell_amount']):
                log_message(order)
                return jsonify( False )
        
            
    # Make sure that you end up executing all resulting transactions!
    
    return txes
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )

    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

 
    for algo_tx in algo_txes:
        order_dict = {}
        order_dict['buy_currency'] = "Ethereum"
        order_dict['sell_currency'] = "Algorand"
        order_dict['sender_pk'] = algo_pk
        order_dict['receiver_pk'] = eth_pk
        order_dict['buy_amount'] = algo_tx['buy_amount']
        order_dict['sell_amount'] = algo_tx['sell_amount']
        acl = connect_to_algo()
        order_dict['tx_id'] = send_tokens_algo(acl, algo_pk , algo_tx)
        txes.append(order_dict)
          
        g.session.add(algo_tx_id)
        g.session.commit()
        
    for eth_tx in eth_txes:
        order_dict = {}
        order_dict['buy_currency'] = "Algorand"
        order_dict['sell_currency'] = "Ethereum"
        order_dict['sender_pk'] = eth_pk
        order_dict['receiver_pk'] = algo_pk
        order_dict['buy_amount'] = eth_tx['buy_amount']
        order_dict['sell_amount'] = eth_tx['sell_amount']
        w3 = connect_to_eth()
        order_dict['tx_id'] = send_tokens_eth(w3, eth_sk, eth_tx) 
        txes.append(order_dict)
  
        g.session.add(eth_tx)
        g.session.commit()
    
    pass

""" End of Helper methods"""


# In[ ]:


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            #eth_sk,eth_pk = get_eth_keys(filename = "eth_mnemonic.txt")
            eth_sk,eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk,algo_pk = get_algo_keys()
            return jsonify( algo_pk )


# In[ ]:


@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk","sender_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        result_check = False
        payload = content['payload']
        sig = content['sig']
        result_check = valid_signature(payload,sig)
        
        # 2. Add the order to the table
        if(result_check):
            order = {}
            order['sender_pk'] = payload['sender_pk']
            order['receiver_pk'] = payload['receiver_pk']
            order['buy_currency'] = payload['buy_currency']
            order['sell_currency'] = payload['sell_currency']
            order['buy_amount'] = payload['buy_amount']
            order['sell_amount'] = payload['sell_amount']
            order['signature'] = sig
            order['tx_id'] = payload['tx_id']
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)


        # 3b. Fill the order (as in Exchange Server II) if the order is valid
            txes = fill_order(order,txes=[])
        
        # 4. Execute the transactions
            execute_txes(txes)
        # If all goes well, return jsonify(True). else return jsonify(False)
            return jsonify(True)
        else:
            log_message(content)
        
        if(result_check):
            return jsonify(True)
        else:
            return jsonify(False)


# In[ ]:


@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk","sender_pk"]
        
    # Same as before
    temp = g.session.query(Order)
    mydict = []
    for myquery in temp.all():
        myorder = {}
        myorder['buy_currency'] = getattr(myquery,'buy_currency')
        myorder['sell_currency'] =  getattr(myquery,'sell_currency')
        myorder['buy_amount'] =  getattr(myquery,'buy_amount')
        myorder['sell_amount'] =  getattr(myquery,'sell_amount')
        myorder['sender_pk'] =  getattr(myquery,'sender_pk')
        myorder['receiver_pk'] =  getattr(myquery,'receiver_pk')
        myorder['signature'] =  getattr(myquery,'signature')
        myorder['tx_id'] =  getattr(myquery,'tx_id')
        mydict.append(myorder)
    result_order_book = { 'data': mydict } 
    #print(result_order_book) 
    #print(" this is jsonify(result_order_book) = ",jsonify(result_order_book))
    return jsonify(result_order_book)
    pass

if __name__ == '__main__':
    app.run(port='5002')


# In[12]:



