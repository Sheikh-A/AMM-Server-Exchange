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

def time_stop_algo(c, token_id):
    wait_num = c.status().get('last-round')
    token_data = c.pending_transaction_info(token_id)
    while not (token_data.get('confirmed-round') and token_data.get('confirmed-round') > 0):
        print("Waiting for confirmation")
        wait_num += 1
        c.status_after_block(wait_num)
        token_data = c.pending_transaction_info(token_id)
    print("Transaction {} confirmed in round {}.".format(token_id, token_data.get('confirmed-round')))
    return token_data


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    mnemonic_secret = "chuckle welcome exchange bless pink segment brand patrol salon aerobic other will present banana bachelor dream almost noble melt alien enter excess during ability trouble"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = account.address_from_private_key(algo_sk)
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    eth_mnemonic = "song funny orchard upon glide burden section cherry glance nice chef drift"
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct = w3.eth.account.from_mnemonic(eth_mnemonic)
    eth_pk = acct._address
    eth_sk = acct._private_key.hex()
    return eth_sk, eth_pk


def check_sig(payload, sig):
    platform = payload["platform"]
    sender_pk = payload["sender_pk"]
    sig_right = False
    # check sig
    if platform == "Ethereum":
        msg = json.dumps(payload)
        eth_encoded_msg = eth_account.messages.encode_defunct(text=msg)
        get_account = eth_account.Account.recover_message(signable_message=eth_encoded_msg, signature=sig)
        if sender_pk == get_account:
            sig_right = True
    if platform == "Algorand":
        msg = json.dumps(payload)
        if algosdk.util.verify_bytes(msg.encode('utf-8'), sig, sender_pk):
            sig_right = True
    return sig_right


def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    result = get_all_match_orders(order)
    if len(result) > 0:
        sorted(result, key=lambda o: o.sell_amount, reverse=True)
        existing_order = result[0]
        # Set the filled field to be the current timestamp on both orders
        current_time = datetime.now()
        existing_order.filled = current_time
        order.filled = current_time
        # Set counterparty_id to be the id of the other order
        order.counterparty_id = existing_order.id
        existing_order.counterparty_id = order.id
        # Create a new order for remaining balance
        new_order = None
        if existing_order.buy_amount > order.sell_amount:
            new_order = Order()
            differ = existing_order.buy_amount - order.sell_amount
            new_order.buy_amount = differ
            sell_amount = differ * existing_order.sell_amount / existing_order.buy_amount
            new_order.sell_amount = sell_amount
            new_order.creator_id = existing_order.id
            new_order.sell_currency = existing_order.sell_currency
            new_order.buy_currency = existing_order.buy_currency
            new_order.receiver_pk = existing_order.receiver_pk
            new_order.sender_pk = existing_order.sender_pk
        if existing_order.buy_amount < order.sell_amount:
            new_order = Order()
            differ = order.sell_amount - existing_order.buy_amount
            new_order.sell_amount = differ
            buy_amount = differ * order.buy_amount / order.sell_amount
            new_order.buy_amount = buy_amount
            new_order.creator_id = order.id
            new_order.sell_currency = order.sell_currency
            new_order.buy_currency = order.buy_currency
            new_order.receiver_pk = order.receiver_pk
            new_order.sender_pk = order.sender_pk
        if new_order != None:
            g.session().add(new_order)
        g.session().commit()


def get_all_match_orders(order):
    """
    get all matched orders
    :param order:
    :return:list
    """
    # existing_order.buy_currency == order.sell_currency
    # existing_order.sell_currency == order.buy_currency
    # taker
    session = g.session()
    cur_res = order.buy_amount / order.sell_amount
    res = session.query(Order).filter(Order.filled == None, Order.buy_currency == order.sell_currency,
                                      Order.sell_currency == order.buy_currency).all()
    result = []
    if len(res) > 0:
        for obj in res:
            # maker
            tmp_res = obj.sell_amount / obj.buy_amount
            if tmp_res >= cur_res:
                result.append(obj)
    return result


def insert_order(payload, sig):
    session = g.session()
    order_dict = {}
    order_dict['sender_pk'] = payload['sender_pk']
    order_dict['receiver_pk'] = payload['receiver_pk']
    order_dict['buy_currency'] = payload['buy_currency']
    order_dict['sell_currency'] = payload['sell_currency']
    order_dict['buy_amount'] = payload['buy_amount']
    order_dict['sell_amount'] = payload['sell_amount']
    order_dict['signature'] = sig
    obj = Order()
    for r in order_dict.keys():
        obj.__setattr__(r, order_dict[r])
    session.add(obj)
    session.commit()
    return obj


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)
    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    algo_txids=send_tokens_algo(g.acl, algo_sk, algo_txes)
    eth_txids=send_tokens_eth(g.w3, eth_sk, eth_txes)


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
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


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
        check_flag = check_sig(payload, sig)
        # 2. Add the order to the table
        order = None
        if check_flag:
            order = insert_order(payload, sig)
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