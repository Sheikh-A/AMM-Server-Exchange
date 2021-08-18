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
from algosdk import mnemonic
from algosdk import account
from web3 import Web3

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

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

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)
    # TODO: Add message to the Log table
    obj = Log()
    for r in message_dict.keys():
        obj.__setattr__(r, message_dict[r])
    session = g.session()
    session.add(obj)
    session.commit()

# def time_stop_algo(c, token_id):
#     wait_num = c.status().get('last-round')
#     token_data = c.pending_transaction_info(token_id)
#     while not (token_data.get('confirmed-round') and token_data.get('confirmed-round') > 0):
#         print("Waiting for confirmation")
#         wait_num += 1
#         c.status_after_block(wait_num)
#         token_data = c.pending_transaction_info(token_id)
#     print("Transaction {} confirmed in round {}.".format(token_id, token_data.get('confirmed-round')))
#     return token_data





def get_eth_keys(filename="eth_mnemonic.txt"):
    # TODO: Generate or read (using the mnemonic secret)
    eth_mnemonic = "song funny orchard upon glide burden section cherry glance nice chef drift"
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    
    acct = w3.eth.account.from_mnemonic(eth_mnemonic)
    #PK SK
    eth_sk = acct._private_key.hex()
    eth_pk = acct._address
    # print(sk)
    # print(pk)
    return eth_sk, eth_pk

def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    mnemonic_secret = "chuckle welcome exchange bless pink segment brand patrol salon aerobic other will present banana bachelor dream almost noble melt alien enter excess during ability trouble"
    
    #MNE
    sk_algo = mnemonic.to_private_key(mnemonic_secret)
    #PRIVATE
    pk_algo = account.address_from_private_key(sk_algo)
    
    return sk_algo, pk_algo


def signature_verify(payload, sig):

    sender_pk = payload["sender_pk"]
    platform = payload["platform"]
    
    correct_input = False
    #ALGO
    if platform == "Algorand":
        msg = json.dumps(payload)
        if algosdk.util.verify_bytes(msg.encode('utf-8'), sig, sender_pk):
            correct_input = True
    elif platform == "Ethereum":
        msg = json.dumps(payload)
        eth_msg = eth_account.messages.encode_defunct(text=msg)
        account_info = eth_account.Account.recover_message(signable_message=eth_msg, signature=sig)
        if account_info == sender_pk:
            correct_input = True
    else:
        print("Check signature")
    return correct_input


def matched_orders(order):
    session = g.session()
    data = order.buy_amount / order.sell_amount
    orderinfo = session.query(Order).filter(Order.filled == None,order.sell_currency == Order.buy_currency, order.buy_currency == Order.sell_currency).all()
    order_dictionary = []
    if len(orderinfo) > 0:
        for item in orderinfo:
            stepfunction = item.sell_amount / item.buy_amount
            if data <= stepfunction:
                #Append item
                order_dictionary.append(item)
    #retutrn order_dictionary
    return order_dictionary

def add_order(p, signature):
    session = g.session()
    order_dict = {}
    order_dict['signature'] = signature

    order_dict['buy_currency'] = p['buy_currency']
    order_dict['sell_currency'] = p['sell_currency']

    order_dict['sender_pk'] = p['sender_pk']
    order_dict['receiver_pk'] = p['receiver_pk']

    order_dict['buy_amount'] = p['buy_amount']
    order_dict['sell_amount'] = p['sell_amount']
    
    order_data = Order()

    for item in order_dict.keys():
        order_data.__setattr__(item, order_dict[item])
    
    session.add(order_data)
    session.commit()
    return order_data

def fill_order(order, txes=[]):
    # TODO: 
    data = matched_orders(order)
    #check if data > 0
    if len(data) < 0:
        print("check input")
        pass
    if len(data) > 0:
        #sort data
        sorted(data,key=lambda o:o.sell_amount,reverse=True)
        
        #first order
        order_current = data[0]
        timestamp = datetime.now()
        
        order.filled = timestamp
        order_current.filled = timestamp
        
        #Flip metrics
        order.counterparty_id = order_current.id
        order_current.counterparty_id = order.id
        
        #Create next order        
        order_next = None

        if order.sell_amount < order_current.buy_amount:
            #create next order
            order_next = Order()
            
            delta = (order_current.buy_amount - order.sell_amount)
            order_next.creator_id = order_current.id
            order_next.buy_amount = delta
            #Sell amount
            sell_amount = delta * order_current.sell_amount / order_current.buy_amount
            order_next.sell_amount = sell_amount
            #Currency
            order_next.buy_currency = order_current.buy_currency
            order_next.sell_currency = order_current.sell_currency
            #Send            
            order_next.sender_pk = order_current.sender_pk
            order_next.receiver_pk = order_current.receiver_pk
            
        if  order.sell_amount > order_current.buy_amount:
            order_next = Order()
            #subtract
            order_next.creator_id = order.id
            delta = order.sell_amount - order_current.buy_amount

            buy_amount = ((delta * order.buy_amount) / order.sell_amount)
            
            order_next.buy_amount = buy_amount
            order_next.sell_amount = delta
            
            order_next.receiver_pk = order.receiver_pk
            order_next.sender_pk = order.sender_pk
            
            order_next.sell_currency = order.sell_currency
            order_next.buy_currency = order.buy_currency
            
        if order_next != None:
            g.session().add(order_next)
        g.session().commit()


def execute_txes(txes):
    if (len(txes) == 0) or (txes is None):
        return True
    
    sk_algo, pk_algo = get_algo_keys()
    eth_sk, eth_pk = get_eth_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print(tx['platform'] for tx in txes)
    #ETH     
    eth_transactions = [tokens for tokens in txes if tokens['platform'] == "Ethereum"]
    #Algo
    algo_transactions = [tokens for tokens in txes if tokens['platform'] == "Algorand"]
    
    # algo_txids=send_tokens_algo(g.acl, sk_algo, algo_transactions)
    # eth_txids=send_tokens_eth(g.w3, eth_sk, eth_transactions)


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            eth_sk, eth_pk = get_eth_keys()
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            # Your code here
            sk_algo, pk_algo = get_algo_keys()
            return jsonify(pk_algo)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    # get_keys()
    if request.method == "POST":
        session = g.session()
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here
        # 1. Check the signature
        sig = content["sig"]
        payload = content["payload"]
        check_flag = signature_verify(payload, sig)
        # 2. Add the order to the table
        order = None
        if check_flag:
            order = add_order(payload, sig)
        else:
            return jsonify(False)
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        check_tx=False
        get_tx=None
        if payload["platform"] == '':
            get_tx = g.w3.eth.get_transaction(order.tx_id)
            if get_tx == None:
                return jsonify(False)
            else:
                if get_tx['to'] == order.receiver_pk and get_tx['value'] == order.sell_amount:
                    check_tx=True
        if payload["platform"] == 'Algorand':
            icl = connect_to_algo(connection_type='indexer')
            get_tx=icl.search_transaction(order.tx_id)
            for tx in get_tx['transactions']:
                if 'payment-transaction' in tx.keys():
                    if tx['payment-transaction']['amount'] == order.sell_amount and tx['payment-transaction'][
                        'receiver'] == order.receiver_pk:
                        check_tx=True
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        if check_tx:
            fill_order(order,get_tx)
        # 4. Execute the transactions
            execute_txes(get_tx)
        # If all goes well, return jsonify(True). else return jsonify(False)
    return jsonify(True)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk"]

    # Same as before
    result = {}
    session = g.session()
    data = session.query(Order).all()
    datas = []
    for obj in data:
        order_dict = {}
        order_dict['sender_pk'] = obj.sender_pk
        order_dict['receiver_pk'] = obj.receiver_pk
        order_dict['buy_currency'] = obj.buy_currency
        order_dict['sell_currency'] = obj.sell_currency
        order_dict['buy_amount'] = obj.buy_amount
        order_dict['sell_amount'] = obj.sell_amount
        order_dict['signature'] = obj.signature
        order_dict['tx_id'] = obj.tx_id
        datas.append(order_dict)
    result["data"] = datas
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')