'''
Author: Daniel Chisner
Date: 2025 04 12

Summary:
This Lambda function automates the management of Windows EC2 instance 
passwords in AWS. When triggered by an instance launch event, the 
function retrieves and decrypts the Windows administrator password 
using RSA decryption with a private key stored in AWS Systems Manager 
Parameter Store. The function first waits for the password data to 
become available (up to 10 minutes as it can take some time), then 
fetches the encrypted password from the EC2 instance. After successful 
decryption, it securely stores the password in SSM Parameter Store under 
a path specific to the instance ID. The function includes integration with 
Auto Scaling Groups through lifecycle hooks, ensuring that password 
processing is completed before the instance is put into service. 
Comprehensive error handling and logging are implemented throughout 
the process to track execution and troubleshoot issues. 
'''

# Import required AWS SDK and utility libraries
import boto3
import json
import os
import logging
import base64
import rsa

# Configure logging for the Lambda function
logger = logging.getLogger()
logger.setLevel(logging.INFO)

"""
Decrypts an EC2 Windows password using RSA private key
Args:
    encrypted_password: Base64 encoded encrypted password
    private_key_pem: RSA private key in PEM format
Returns:
    Decrypted password as string
"""

def decrypt_password(encrypted_password, private_key_pem):
    try:
        # Decode the base64 encrypted password
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        
        # Convert PEM string to RSA private key object
        private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode('utf-8'))
        
        # Perform RSA decryption on password
        decrypted_password = rsa.decrypt(encrypted_password_bytes, private_key)
        
        return decrypted_password.decode('utf-8')
    except Exception as e:
        logger.error(f"Error decrypting password: {str(e)}")
        raise e

"""
Main Lambda handler function that processes incoming events
"""
def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Route event based on type
    if 'detail-type' in event:
        return handle_instance_launch(event)
    else:
        logger.error("Unexpected event type received")
        raise Exception("Invalid event type")

"""
Handles EC2 instance launch events by retrieving and storing Windows passwords
Args:
    event: EventBridge event containing instance launch details
"""

def handle_instance_launch(event):
    try:
        # Initialize AWS service clients
        ec2 = boto3.client('ec2')
        ssm = boto3.client('ssm')
        autoscaling = boto3.client('autoscaling')
        
        # Extract instance details from event
        detail = event.get('detail', {})
        instance_id = detail.get('EC2InstanceId')
        
        # Validate instance ID
        if not instance_id:
            logger.error("No EC2 instance ID found in event")
            return
            
        logger.info(f"Processing instance: {instance_id}")
        
        # Retrieve private key from SSM Parameter Store
        key_pair_parameter_name = os.environ['KEY_PAIR_PARAMETER_NAME']
        private_key_pem = ssm.get_parameter(
            Name=key_pair_parameter_name,
            WithDecryption=True
        )['Parameter']['Value']
        
        logger.info("Retrieved private key from SSM")
        
        # Wait for Windows password to become available
        logger.info(f"Waiting for password data for instance {instance_id}")
        waiter = ec2.get_waiter('password_data_available')
        waiter.wait(
            InstanceId=instance_id,
            WaiterConfig={'Delay': 15, 'MaxAttempts': 40} # Wait up to 10 minutes
        )
        
        # Retrieve encrypted password from EC2
        password_data = ec2.get_password_data(InstanceId=instance_id)
        encrypted_password = password_data['PasswordData']
        
        if encrypted_password:
            logger.info("Retrieved encrypted password, attempting to decrypt")
            
            try:
                # Decrypt Windows password
                decrypted_password = decrypt_password(encrypted_password, private_key_pem)

                logger.info("Successfully decrypted Windows password")
                
                # Store decrypted password in SSM Parameter Store
                ssm.put_parameter(
                    Name=f"/EC2/Passwords/{instance_id}",
                    Value=decrypted_password,
                    Type='SecureString',
                    Overwrite=True
                )
                
                logger.info(f"Successfully stored decrypted password for instance {instance_id}")
                
            except Exception as decrypt_error:
                logger.error(f"Failed to decrypt password: {str(decrypt_error)}")
                raise decrypt_error
            
            # Complete ASG lifecycle hook if present
            if detail.get('LifecycleHookName'):
                logger.info("Completing lifecycle hook")
                autoscaling.complete_lifecycle_action(
                    LifecycleHookName=detail['LifecycleHookName'],
                    AutoScalingGroupName=detail['AutoScalingGroupName'],
                    InstanceId=instance_id,
                    LifecycleActionResult='CONTINUE'
                )
                logger.info("Lifecycle hook completed")
                
        return {
            'statusCode': 200,
            'body': json.dumps('Password processing completed successfully')
        }
        
    except Exception as e:
        logger.error(f"Error processing instance password: {str(e)}")
        raise e
