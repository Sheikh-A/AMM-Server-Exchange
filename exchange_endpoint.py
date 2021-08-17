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

# self imported
from algosdk import mnemonic
import web3
from web3 import Web3, HTTPProvider

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth, wait_for_confirmation_eth, wait_for_confirmation_algo, eth_print

from models import Base, Order, TX, Log
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
            print("connect_to_algo()-1")
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
        print("connect_to_algo()-1-e")
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
            print("connect_to_algo()-2")
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')
        print("connect_to_algo()-2-e")

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
            print("connect_to_eth()")
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        print("connect_to_eth()-e")
        
""" End of pre-defined methods """
        
    
    
    
    
    
    
    
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    # msg = json.dumps(message_dict) # generate json string
    # TODO: Add message to the Log table
    order_obj = Log(message=message_dict)
    g.session.add(order_obj)

    
    
    
    
    
    
    
    
    
def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = "such chapter crane ugly uncover fun kitten duty culture giant skirt reunion pizza pill web monster upon dolphin aunt close marble dune kangaroo ability merit"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
    return algo_sk, algo_pk




def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    
    mnemonic_secret = "program gym dash habit possible gate shallow exclude access report cave will"
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key

    return eth_sk, eth_pk    
    
    
    
    
    
    
    
def fill_order(order, txes=[]):
# def fill_order(order):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    # get the order you just inserted from the DB
    current_order = order

    # Check if there are any existing orders that match and add them into a list
    order_list = []
    orders = g.session.query(Order).filter(Order.filled == None).all()
    for existing_order in orders:
        # if ((existing_order.buy_amount != 0) and (current_order.sell_amount != 0)):
        if ((existing_order.buy_currency == current_order.sell_currency)
                and (existing_order.sell_currency == current_order.buy_currency)
                and (existing_order.sell_amount / existing_order.buy_amount
                     >= current_order.buy_amount / current_order.sell_amount)
                and (existing_order.counterparty_id == None)):
            order_list.append(existing_order)

    # If a match is found between order and existing_order
    if (len(order_list) > 0):
        match_order = order_list[0]

        # Set the filled field to be the current timestamp on both orders
        # Set counterparty_id to be the id of the other order
        match_order.filled = datetime.now()
        current_order.filled = datetime.now()
        match_order.counterparty_id = current_order.id
        current_order.counterparty_id = match_order.id
        g.session.commit()
        
        
            

        # If match_order is not completely filled
        if (current_order.sell_amount < match_order.buy_amount):
            diff = match_order.buy_amount - current_order.sell_amount
            exchange_rate_match = match_order.sell_amount / match_order.buy_amount
            sell_amount_new_match = diff * exchange_rate_match
            new_order = Order(sender_pk=match_order.sender_pk,
                              receiver_pk=match_order.receiver_pk,
                              buy_currency=match_order.buy_currency,
                              sell_currency=match_order.sell_currency,
                              buy_amount=diff,
                              sell_amount=sell_amount_new_match,
                              creator_id=match_order.id, 
                              tx_id=match_order.tx_id)
            g.session.add(new_order)
            g.session.commit()
            
            # since we find a match, create transactions
            tx1_dict = {'platform': current_order.buy_currency, 'receiver_pk': current_order.receiver_pk, 'order_id': current_order.id, 'amount': current_order.buy_amount}
            tx2_dict = {'platform': match_order.buy_currency, 'receiver_pk': match_order.receiver_pk, 'order_id': match_order.id, 'amount': current_order.sell_amount}
            txes.append(tx1_dict)
            txes.append(tx2_dict)
            
            print("M")
            print(current_order.id)
            print(match_order.id)
            print()
            next_order = g.session.query(Order).order_by(Order.id.desc()).first()
            fill_order(next_order, txes)

        # If current_order is not completely filled
        elif (current_order.buy_amount > match_order.sell_amount):
            # print("_current_order is not completely filled")
            diff = current_order.buy_amount - match_order.sell_amount
            exchange_rate_current = current_order.buy_amount / current_order.sell_amount
            sell_amount_new_current = diff / exchange_rate_current
            new_order = Order(sender_pk=current_order.sender_pk,
                              receiver_pk=current_order.receiver_pk,
                              buy_currency=current_order.buy_currency,
                              sell_currency=current_order.sell_currency,
                              buy_amount=diff,
                              sell_amount=sell_amount_new_current,
                              creator_id=current_order.id, 
                              tx_id=current_order.tx_id)
            g.session.add(new_order)
            g.session.commit()
            
            # since we find a match, create transactions
            tx1_dict = {'platform': current_order.buy_currency, 'receiver_pk': current_order.receiver_pk, 'order_id': current_order.id, 'amount': match_order.sell_amount}
            tx2_dict = {'platform': match_order.buy_currency, 'receiver_pk': match_order.receiver_pk, 'order_id': match_order.id, 'amount': match_order.buy_amount}
            txes.append(tx1_dict)
            txes.append(tx2_dict)
            
            print("C")
            print(current_order.id)
            print(match_order.id)
            print()
            next_order = g.session.query(Order).order_by(Order.id.desc()).first()
            fill_order(next_order, txes)
            
        # if both orders can completely fill each other
        # no child order needs to be generated
        else:
            # since we find a match, create transactions
            tx1_dict = {'platform': current_order.buy_currency, 'receiver_pk': current_order.receiver_pk, 'order_id': current_order.id, 'amount': current_order.buy_amount}
            tx2_dict = {'platform': match_order.buy_currency, 'receiver_pk': match_order.receiver_pk, 'order_id': match_order.id, 'amount': match_order.buy_amount}
            txes.append(tx1_dict)
            txes.append(tx2_dict)
            
            print("E")
            print(current_order.id)
            print(match_order.id)
            print()
  
    
    
    
    
    
    
    
    
    
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
    
    print('testtest')
    print(len(algo_txes))
    print(len(eth_txes))
    
    print("\nalgo_txes\n")
    print_tx_list(algo_txes)
    print("\neth_txes\n")
    print_tx_list(eth_txes)
    
    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    
    algo_tx_ids = send_tokens_algo( g.acl, algo_sk, algo_txes)
    print(len(algo_tx_ids))
    print(algo_tx_ids)
    print(algo_tx_ids[0])
    print()
    
    for i, tx_dict in enumerate(algo_txes):
        print(type(algo_tx_ids[i]))
        print(algo_tx_ids[i])
        tx = TX(platform = tx_dict['platform'],
                 receiver_pk = tx_dict['receiver_pk'],
                 order_id = tx_dict['order_id'], 
                 tx_id = algo_tx_ids[i])
        g.session.add(tx)
        g.session.commit()
    
    eth_tx_ids = send_tokens_eth( g.w3, eth_sk.hex(), eth_txes)
    print(len(eth_tx_ids))
    print(eth_tx_ids)
    print(eth_tx_ids[0])
    print()

    for i, tx_dict in enumerate(eth_txes):
        print(type(eth_tx_ids[i]))
        print(eth_tx_ids[i])
        tx = TX(platform = tx_dict['platform'],
                 receiver_pk = tx_dict['receiver_pk'],
                 order_id = tx_dict['order_id'], 
                 tx_id = eth_tx_ids[i])
        g.session.add(tx)
        g.session.commit()
        
    









# check whether “sig” is a valid signature of json.dumps(payload),
# using the signature algorithm specified by the platform field.
# Be sure to verify the payload using the sender_pk.
def check_sig(payload,sig):
    
    pk = payload['sender_pk']
    platform = payload['platform']
    payload_json = json.dumps(payload)
    result = False
    
    if platform == "Algorand":
        print("Algorand")
        if algosdk.util.verify_bytes(payload_json.encode('utf-8'), sig, pk):
            print("Algo sig verifies!")
            result = True

    elif platform == "Ethereum":
        print("Ethereum")
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload_json)
        if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == pk:
            print("Eth sig verifies!")
            result = True
    
    return result, payload_json



# convert a row in DB into a dict
def row2dict(row):
    return {
        c.name: getattr(row, c.name)
        for c in row.__table__.columns
    }



# print a dictionary nicely
def print_dict(d):
    for key, value in d.items():
        print(key, ' : ', value)


# print a list of tx
def print_tx_list(txes):
    print(len(txes))
    for tx in txes:
        print(type(tx))
        print_dict(tx)
        print()
        
""" End of Helper methods"""












# You will need to generate a key-pair on both the Ethereum and Algorand blockchains (see more details below).
# The endpoint “/address” should accept a (JSON formatted) request with the argument “platform.” 
# The endpoint should return a (JSON formatted) response with the exchange server’s public-key on the specified platform (either ‘Ethereum’ or ‘Algorand’).
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        print("--------- address ---------")
        content = request.get_json(silent=True)
        
        # check whether the input content contains a 'platform'
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        
        # check whether the input platform is "Ethereum" or "Algorand"
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            eth_keys = get_eth_keys()
            eth_sk = eth_keys[0]
            eth_pk = eth_keys[1]
            print( "return server eth address" )
            print(eth_sk)
            print("eth_pk \n" + eth_pk)
            return jsonify( eth_pk )
        
        if content['platform'] == "Algorand":
            #Your code here
            algo_keys = get_algo_keys()
            algo_sk = algo_keys[0]
            algo_pk = algo_keys[1]
            print( "return server algo address" )
            print(algo_sk)
            print("algo_pk \n" + algo_pk)
            return jsonify( algo_pk )

        
        
        
# should accept POST data in JSON format.
# Orders should have two fields “payload” and "sig".
# The payload must contain the following fields, 
# 'sender_pk’,’receiver_pk,’buy_currency’,’sell_currency’,’buy_amount’,’sell_amount’,’tx_id’,

# As in the previous assignment, the platform must be either “Algorand” or "Ethereum". 
# Your code should check whether “sig” is a valid signature of json.dumps(payload), using the signature algorithm specified by the platform field.
# If the signature verifies, the remaining fields should be stored in the “Order” table.
# If the signature does not verify, Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_eth_keys()
    get_algo_keys() 
    if request.method == "POST":
        print("--------- trade ---------")
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        
        # Orders should have two fields “payload” and "sig".
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # The payload must contain the following fields, 
        # 'sender_pk’,’receiver_pk,’buy_currency’,’sell_currency’,’buy_amount’,’sell_amount’,’tx_id’,
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # extract contents from json
        sig = content['sig']
        payload = content['payload']
        platform = payload['platform']

        # The platform must be either “Algorand” or "Ethereum".
        platforms = ["Algorand", "Ethereum"]
        if not platform in platforms:
            print("input platform is not Algorand or Ethereum")
            return jsonify(False)
        
        # check signature
        check_result = check_sig(payload,sig)
        result = check_result[0]
        payload_json = check_result[1]
        
        # 2. Add the order to the table
        
        # If the signature does not verify, do not insert the order into the “Order” table.
        # Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        if result is False:
            print("signature does NOT verify")
            log_message(payload_json)            
            return jsonify(result)
        
        # If the signature verifies, store the signature,
        # as well as all of the fields under the ‘payload’ in the “Order” table EXCEPT for 'platform’.
        if result is True:
            print("signature verifies")
            order_obj = Order(sender_pk=payload['sender_pk'],
                              receiver_pk=payload['receiver_pk'],
                              buy_currency=payload['buy_currency'],
                              sell_currency=payload['sell_currency'],
                              buy_amount=payload['buy_amount'],
                              sell_amount=payload['sell_amount'],
                              tx_id=payload['tx_id'],
                              signature=sig)            
            g.session.add(order_obj)
    
            # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            # In this assignment, the “/trade” endpoint should take an additional field “tx_id” which specifies the transaction ID 
            # (sometimes called the transaction hash) of the transaction that deposited tokens to the exchange. 

            # In particular, before filling an order, you must check
            # The transaction specified by tx_id is a valid transaction on the platform specified by ‘sell_currency’
            # The amount of the transaction is ‘sell_amount’
            # The sender of the transaction is ‘sender_pk’
            # The receiver of the transaction is the exchange server (i.e., the key specified by the ‘/address’ endpoint)

            # 3b. Fill the order (as in Exchange Server II) if the order is valid
            txes = []
            current_order = g.session.query(Order).order_by(Order.id.desc()).first()
            fill_order(current_order, txes)

            # 4. Execute the transactions
            execute_txes(txes)

            # If all goes well, return jsonify(True). else return jsonify(False)
            return jsonify(True)

    
    
    
# should return a list of all orders in the database (the “Order” table). 
# The response should be a list of orders formatted as JSON. 
# Each order should be a dict with (at least) the seven key fields referenced above 
# (‘sender_pk’,’receiver_pk’,’buy_currency’,’sell_currency’,’buy_amount’,’sell_amount’,’tx_id’).
@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    
    # Same as before
    print("--------- order_book ---------")
        
    # get orders from DB into a list
    order_dict_list = [
           row2dict(order)
           for order in g.session.query(Order).all()
    ]
        
    # add the list into a dict
    result = {
        'data': order_dict_list
    }    
    
    print("order book length: ")
    print(len(order_dict_list))
    print()
    for order_dict in order_dict_list:
        print_dict(order_dict)
        print()
    
    #############
    
    tx_dict_list = [
           row2dict(tx)
           for tx in g.session.query(TX).all()
    ]
    
    # add the list into a dict
    tx_result = {
        'data': tx_dict_list
    }    
    
    print("TX book length: ")
    print(len(tx_dict_list))
    print()
    for tx_dict in tx_dict_list:
        print_dict(tx_dict)
        print()
   
    return jsonify(result)








if __name__ == '__main__':
    app.run(port='5002')