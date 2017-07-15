import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_pem(keysize):
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=keysize)
    pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    private = pem.decode('utf-8')
    public = pub.decode('utf-8')
    return private, public

 
def handler(event, context):
    responseStatus = 'SUCCESS'
    responseData = {}
    if event['RequestType'] == 'Delete':
        sendResponse(event, context, responseStatus, responseData)
 
    responseData = {'Success': 'Test Passed.'}
    sendResponse(event, context, responseStatus, responseData)
 
def sendResponse(event, context, responseStatus, responseData):
    responseData['PEM'],responseData['PUB'] = generate_pem(2048)
    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': context.log_stream_name,
                    'StackId': event['StackId'],
                    'RequestId': event['RequestId'],
                    'LogicalResourceId': event['LogicalResourceId'],
                    'Data': responseData}
    print 'RESPONSE BODY:n' + json.dumps(responseBody)
    try:
        req = requests.put(event['ResponseURL'], data=json.dumps(responseBody))
        if req.status_code != 200:
            print req.text
            raise Exception('Recieved non 200 response while sending response to CFN.')
        return
    except requests.exceptions.RequestException as e:
        print e
        raise
 
if __name__ == '__main__':
    handler('event', 'handler')
