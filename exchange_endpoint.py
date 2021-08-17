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
from algosdk.v2client import indexer
import traceback
from algosdk import mnemonic, v2client

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from web3 import Web3
from web3.auto import w3

import send_tokens
from database_endpoint import session
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
    log_obj = Log(message=msg)
    session.add(log_obj)
    session.commit()
    # TODO: Add message to the Log table
    return


def is_valid_order(existing_order):
    sell_currency = existing_order.sell_currency
    if sell_currency != "Ethereum" and sell_currency != "Algorand":
        return False
    return True


def insert_order_to_db(order):
    order_obj = Order(sender_pk=order['payload']['sender_pk'], receiver_pk=order['payload']['receiver_pk'],
                      buy_currency=order['payload']['buy_currency'], sell_currency=order['payload']['sell_currency'],
                      buy_amount=order['payload']['buy_amount'], sell_amount=order['payload']['sell_amount'],
                      tx_id=order['payload']['tx_id'])
    session.add(order_obj)
    session.commit()


def verifyEth(content):
    valid_eth = False
    eth_pk = content['payload']['sender_pk']
    payload = content['payload']
    payload = json.dumps(payload)
    eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=content['sig']) == eth_pk:
        print("Eth sig verifies!")
        valid_eth = True
    return valid_eth


def verifyAlg(content):
    payload = content['payload']
    algo_sig_str = content['sig']
    algo_pk = payload['sender_pk']
    payload = json.dumps(payload)
    if algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig_str, algo_pk):
        print("Algo sig verifies!")
        return True
    return False


def get_keys():
    pass


def get_algo_keys():
    mnemonic_secret = "chuckle welcome exchange bless pink segment brand patrol salon aerobic other will present banana bachelor dream almost noble melt alien enter excess during ability trouble"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    w3 = Web3()
    #    # TODO: Generate or read (using the mnemonic secret)
    #    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct, mnemonic_secret = w3.eth.account.create_with_mnemonic()
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk



def verify_transaction(content):
    platform = content['payload']['sell_currency']
    sell_amount = content['payload']['sell_amount']
    tx_id = content['payload']['tx_id']
    if platform == "Algorand":
        # need to insert algo verification
        return True

    if platform == 'Ethereum':
        tx = w3.eth.get_transaction(tx_id)
        if tx['value'] == sell_amount:
            return True
    else:
        return False


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

    algod_client = send_tokens.connect_to_algo(connection_type='')
    send_tokens.send_tokens_algo(g.acl, algo_sk, algo_txes)


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
            eth_sk, eth_pk = get_eth_keys("a")
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        # content = {'sig': signature,
        #        'payload': {'sender_pk': "TWYS3Y6SJOUW6WIEIXTBOII7523QI4MUO3TSYDS7SCG4TIGGC2S6V6TJP4",
        #                    'receiver_pk': "0xB7F6617dc26C3C609c8837E45eE9D061Eb7a9D9b",
        #                    'buy_currency': "Ethereum",
        #                    'sell_currency': "Algorand",
        #                    'buy_amount': 51,
        #                    'sell_amount': 257,
        #                    'tx_id': "LR2CL4OXAMQ2EQVGFRUH27JA6SGUSBTJR7GB56S3NZ5KMGKJVLLA"}}

        content = request.get_json(silent=True)
        # content = {'sig': signature,
        #        'payload': {'sender_pk': "TWYS3Y6SJOUW6WIEIXTBOII7523QI4MUO3TSYDS7SCG4TIGGC2S6V6TJP4",
        #                    'receiver_pk': "0xB7F6617dc26C3C609c8837E45eE9D061Eb7a9D9b",
        #                    'buy_currency': "Ethereum",
        #                    'sell_currency': "Algorand",
        #                    'buy_amount': 51,
        #                    'sell_amount': 257,
        #                    'tx_id': "LR2CL4OXAMQ2EQVGFRUH27JA6SGUSBTJR7GB56S3NZ5KMGKJVLLA"}}
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
        platform = content['payload']['sell_currency']
        if platform == 'Ethereum':
            if verifyEth(content):
                if verify_transaction(content):
                    insert_order_to_db(content)
                    return jsonify(True)
        elif platform == 'Algorand':
            if verifyAlg(content):
                insert_order_to_db(content)
                return jsonify(True)
        else:
            log_message(content)
        return jsonify(False)
        # 1. Check the signature

        # 2. Add the order to the table

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid

        # 4. Execute the transactions

        # If all goes well, return jsonify(True). else return jsonify(False)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk"]
    orders = session.query(Order).filter(Order.filled == None).all()
    data = []
    for existing_order in orders:
        if is_valid_order(existing_order):
            sender_pk = existing_order.sender_pk
            receiver_pk = existing_order.receiver_pk
            buy_currency = existing_order.buy_currency
            sell_currency = existing_order.sell_currency
            buy_amount = existing_order.buy_amount
            sell_amount = existing_order.sell_amount
            tx_id = existing_order.tx_id
            signature = existing_order.signature

            orderJson = {
                "sender_pk": sender_pk,
                "receiver_pk": receiver_pk,
                "buy_currency": buy_currency,
                "sell_currency": sell_currency,
                "buy_amount": buy_amount,
                "sell_amount": sell_amount,
                "signature": signature,
                "tx_id": tx_id
            }
            data.append(orderJson)
    result = {"data": data}

    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')