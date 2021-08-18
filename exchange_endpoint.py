from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from algosdk import mnemonic
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from web3 import Web3


#acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()


# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth, check_tx_eth, check_tx_algo

w3 = connect_to_eth()
acl = connect_to_algo(connection_type="indexer")
bcl = connect_to_algo(connection_type="other")

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
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemon_secret = "chuckle welcome exchange bless pink segment brand patrol salon aerobic other will present banana bachelor dream almost noble melt alien enter excess during ability trouble"
    algo_sk = mnemonic.to_private_key(mnemon_secret)
    algo_pk = mnemonic.to_public_key(mnemon_secret)
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    #w3 = Web3()
    
    #w3 = connect_to_eth()
    #w3 = g.w3
    mnemonic_secret = "song funny orchard upon glide burden section cherry glance nice chef drift"
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    print("ETH_SK : " + str(eth_sk))
    #print(eth_pk)
    #print(eth_sk)
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    pass

def create_tx(existing, new_order):
    txes = []
    #print("INSIDE CREATE_TX1")
    tx = { 
                    'platform': existing.buy_currency,
                    'receiver_pk': existing.receiver_pk,
                    'order_id': existing.id,
                    'tx_id': 0, 
                    'send_amount': 0
                    }
    txes.append(tx)
    #print("INSIDE CREATE_TX2")
    tx = { 
                    'platform': new_order.buy_currency,
                    'receiver_pk': new_order.receiver_pk,
                    'order_id': new_order.id,
                    'tx_id': 0, 
                    'send_amount': 0
                    }
    txes.append(tx)
    print("INSIDE CREATE_TX3")
    #if new_order.buy_amount < existing.buy_amount:
    #if new_order.sell_amount < existing.buy_amount:
    if new_order.sell_amount < existing.buy_amount:
        txes[0]['send_amount'] = new_order.sell_amount #existing sell amount is lower so we will send all of order_obj selling 
        txes[1]['send_amount'] = new_order.buy_amount
    
    elif existing.sell_amount < new_order.buy_amount:
    #elif existing.sell_amount < new_order.buy_amount:
        txes[0]['send_amount'] = existing.buy_amount #existing sell amount is lower so we will send all of order_obj selling 
        txes[1]['send_amount'] = existing.sell_amount
    
    else:
        txes[0]['send_amount'] = existing.buy_amount #existing sell amount is lower so we will send all of order_obj selling 
        txes[1]['send_amount'] = new_order.buy_amount
        
    
    print("INSIDE CREATE_TX4")
    return txes
  
def execute_txes(txes):
    #time.sleep(1)
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx.id for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx.sell_currency in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx.sell_currency for tx in txes )

    #algo_txes = [tx for tx in txes if tx.sell_currency == "Algorand" ]
    #eth_txes = [tx for tx in txes if tx.sell_currency == "Ethereum" ]
    existing_order = txes[0]
    new_order = txes[1]
    txes = create_tx(existing_order, new_order)
    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]
    print("TX1 : " + str(txes[0]))
    print("TX2 : " + str(txes[1]))
    print("RECIEVER ADD1: " + str(existing_order.receiver_pk))
    print("RECIEVER ADD2: " + str(new_order.receiver_pk))
                                         
    tx_eth = send_tokens_eth(w3, eth_sk, eth_txes)
    #print("HERE AFTER OBJECT created0")
    order = { 
                    'platform': eth_txes[0]['platform'],
                    'receiver_pk': eth_txes[0]['receiver_pk'],
                    'order_id': eth_txes[0]['order_id'],
                    'tx_id': tx_eth 
              
                    }
    fields = ['platform','receiver_pk','order_id','tx_id']
    #print("HERE AFTER OBJECT created0.5")
    tx_entry = TX(**{f:order[f] for f in fields})
    #print("HERE AFTER OBJECT created1")
    g.session.add(tx_entry)
    #print("HERE AFTER OBJECT created2")
          #g.session.commit()
          #order_loop(order_com)
    g.session.commit()
    
    tx_algo = send_tokens_algo(bcl, algo_sk, algo_txes)
    print("HERE AFTER OBJECT created0")
    order = { 
                    'platform': algo_txes[0]['platform'],
                    'receiver_pk': algo_txes[0]['receiver_pk'],
                    'order_id': algo_txes[0]['order_id'],
                    'tx_id': tx_algo 
              
                    }
    fields = ['platform','receiver_pk','order_id','tx_id']
    print("HERE AFTER OBJECT created0.5")
    tx_entry = TX(**{f:order[f] for f in fields})
    print("HERE AFTER OBJECT created1")
    g.session.add(tx_entry)
    print("HERE AFTER OBJECT created2")
          #g.session.commit()
          #order_loop(order_com)
    g.session.commit()
    
                                         
                                         
                                      
#     if order_obj.buy_amount > existing_order.buy_amount:
#         existing_send = order_obj.sell_amount #existing sell amount is lower so we will send all of order_obj selling 
#         order_send = order_obj.buy_amount
    
#     if existing_order.sell_amount > order_obj.buy_amount:
        
        
        

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

  

def order_loop(order_obj):
  #time.sleep(1)
  
  orders = g.session.query(Order).filter(Order.filled == None).all()
  
  for existing_order in orders:
          #print("NONEFOUND")

          if existing_order.buy_currency == order_obj.sell_currency:
            if existing_order.sell_currency == order_obj.buy_currency:
#               print(existing_order.sell_amount / existing_order.buy_amount)
#               print(order_obj.buy_amount / order_obj.sell_amount)
              if ((existing_order.sell_amount / existing_order.buy_amount) >= (order_obj.buy_amount / order_obj.sell_amount)):
#                 print(existing_order.sell_amount / existing_order.buy_amount)
#                 print(order_obj.buy_amount / order_obj.sell_amount)
#                 print("HEREWEARE")
#                 print(existing_order.id)
                existing_order.filled = datetime.now()
                order_obj.filled = datetime.now()
                existing_order.counterparty_id = order_obj.id 
                order_obj.counterparty_id = existing_order.id
                print("MATCHING ORDER Existing !!!!!!!!!!!!!!!!:" + str(existing_order.buy_amount) + " order id " + str(existing_order.signature))
                print("MATCHING ORDER Existing !!!!!!!!!!!!!!!!:" + str(existing_order.sell_amount) + " order id " + str(existing_order.id))
                print("MATCHING ORDER New !!!!!!!!!!!!!!!!:" + str(order_obj.buy_amount) + " order id " + str(order_obj.signature))
                print("MATCHING ORDER New !!!!!!!!!!!!!!!!:" + str(order_obj.sell_amount) + " order id " + str(order_obj.id))
                txes = [existing_order, order_obj]
                execute_txes(txes)
                if order_obj.sell_amount < existing_order.buy_amount:
                  #order_child = copy.deepcopy(existing_order)
                  order = { 
                    'buy_currency': existing_order.buy_currency,
                    'sell_currency': existing_order.sell_currency, 
                    'buy_amount': existing_order.buy_amount,
                    'sell_amount': existing_order.sell_amount,
                    'sender_pk': existing_order.sender_pk,
                    'receiver_pk': existing_order.receiver_pk
                    }
                  fields = ['buy_currency','sell_currency','buy_amount','sell_amount', 'sender_pk','receiver_pk']
    
                  order_child = Order(**{f:order[f] for f in fields})
                  g.session.add(order_child)
                  g.session.commit()
                  order_child.creator_id = existing_order.id 
                  order_child.filled = None
                  new_buy = existing_order.buy_amount - order_obj.sell_amount
                  ratio = existing_order.sell_amount / existing_order.buy_amount
#                   print("new buy: " + str(new_buy) )
#                   print("ratio: " + str(ratio))
                  new_selling = math.ceil(ratio * new_buy)
                  order_child.buy_amount = new_buy
                  order_child.sell_amount = new_selling
                  g.session.commit()
                  print("order_child1: " + str(order_child.buy_amount))
                  print("order_child1 sell: " + str(order_child.sell_amount)  + " order id " + str(order_child.id))
                  #order_loop(order_child)
                  break
                  
                if existing_order.sell_amount < order_obj.buy_amount:
                  #order_child2 = copy.deepcopy(order_obj)
                  order = { 
                    'buy_currency': order_obj.buy_currency,
                    'sell_currency': order_obj.sell_currency, 
                    'buy_amount': order_obj.buy_amount,
                    'sell_amount': order_obj.sell_amount,
                    'sender_pk': order_obj.sender_pk,
                    'receiver_pk': order_obj.receiver_pk
                    }
                  fields = ['buy_currency','sell_currency','buy_amount','sell_amount', 'sender_pk','receiver_pk']
    
                  order_child2 = Order(**{f:order[f] for f in fields})
                  g.session.add(order_child2)
                  g.session.commit()
                  order_child2.creator_id = order_obj.id 
                  order_child2.filled = None
                  new_buy = order_obj.buy_amount - existing_order.sell_amount
                  ratio = order_obj.buy_amount / order_obj.sell_amount
#                   print("new buy: " + str(new_buy) )
#                   print("ratio: " + str(ratio))
                  #ratio = existing_order.sell_amount / existing_order.buy_amount
                  new_selling = math.ceil(new_buy / ratio)
                  order_child2.buy_amount = new_buy
                  order_child2.sell_amount = new_selling
                  g.session.commit()
                  print("order_child2: " + str(order_child2.buy_amount))
                  print("order_child2 sell: " + str(order_child2.sell_amount)  + " order id " + str(order_child2.id))
                  #order_loop(order_child2)
                break

def verify(content):
    #content = request.get_json(silent=True)

    #Check if signature is valid
    
    result = False
    platform = content['payload']['platform']
    message = content['payload']
    message2 = json.dumps(message)
    pk = content['payload']['sender_pk']
    sig = content['sig']
    if platform == 'Ethereum':
        
        eth_encoded_msg = eth_account.messages.encode_defunct(text=message2)
        if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk:
            result = True
        
    if platform == 'Algorand':
        
        if algosdk.util.verify_bytes(message2.encode('utf-8'),sig,pk):
            result = True
     #Should only be true if signature validates
    #print(result)
    return result 

""" End of Helper methods"""
  
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
#             w3 = connect_to_eth()
#             mnemonic_secret = "thrive million traffic mouse demand suffer now true dice loop dream humble"
#             acct = w3.eth.account.from_mnemonic(mnemonic_secret)
#             eth_pk = acct._address
#             eth_sk = acct._private_key
            eth_sk, eth_pk =  get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
#             mnemon_secret = "borrow praise special vague peace iron speak awake melody famous expose estate undo ceiling carbon myself tomato draw dress neither enlist treat captain above phone"
#             skey = mnemonic.to_private_key(mnemon_secret)
#             algo_pk = mnemonic.to_public_key(mnemon_secret)
            algo_sk, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    #print("HERE IN TRADE")
    print( "In trade", file=sys.stderr )
    #print("HERE IN TRADE2")
    connect_to_blockchains()
    #print("HERE IN TRADE3")
    #get_keys()
    #print("HERE IN TRADE4")
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
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
        #print("content: " + str(content))
        test = verify(content)
        # 2. Add the order to the table
        #print("AFTER VERIFY")
        #print(test)
        if test == False:
            return jsonify(False)
        if test == True:
          #print("WE ARE VERIFIED")
          print(str(content))
     
          order = { 
                    'buy_currency': content['payload']['buy_currency'],
                    'sell_currency': content['payload']['sell_currency'],
                    'buy_amount': content['payload']['buy_amount'],
                    'sell_amount': content['payload']['sell_amount'],
                    'sender_pk': content['payload']['sender_pk'],
                    'receiver_pk': content['payload']['receiver_pk'],
                    'signature': content['sig'],
                    'tx_id': content['payload']['tx_id']
              
                    }
          fields = ['buy_currency','sell_currency','buy_amount','sell_amount', 'sender_pk','receiver_pk', 'signature', 'tx_id']
    
          order_com = Order(**{f:order[f] for f in fields})
          #print("HERE IN TRADE5")
          g.session.add(order_com)
          #g.session.commit()
          #order_loop(order_com)
          g.session.commit()
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        #print("txid in content")
        #print(content['payload']['tx_id'])
        platform = content['payload']['platform']
        information_check = False
        if platform == 'Ethereum':
            information_check = check_tx_eth(w3, content['payload']['tx_id'], content['payload']['sender_pk'], content['payload']['sell_amount'])
            print("Information eth check : " + str(information_check))
            if information_check == False:
                return jsonify(False)
        if platform == 'Algorand':
            information_check = check_tx_algo(acl, content['payload']['tx_id'], content['payload']['sender_pk'], content['payload']['sell_amount'])
            print("Information algo check : " + str(information_check))
            if information_check == False:
                return jsonify(False)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        order_loop(order_com)
        g.session.commit()
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    #print("HERE IN ORDER")
    orders = g.session.query(Order).all()
    
    #key = "data"
    #a.setdefault(key, [])
    
    a = {}
    for ord in orders:
      
      order_detail = {
                      'sender_pk': ord.sender_pk,
                      'receiver_pk': ord.receiver_pk,
                      'buy_currency': ord.buy_currency,
                      'sell_currency': ord.sell_currency,
                      'buy_amount': ord.buy_amount,
                      'sell_amount': ord.sell_amount,
                      'signature': ord.signature,
                      'tx_id': ord.tx_id
        
                      }
      
      a.setdefault("data",[]).append(order_detail)
    #print(a)
      
    
    return jsonify(a)

if __name__ == '__main__':
    app.run(port='5002')