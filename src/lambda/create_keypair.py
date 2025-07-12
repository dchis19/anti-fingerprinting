'''
Author: Daniel Chisner
Date: 2025 04 11

Summary:
This Lambda function manages EC2 key pairs and their secure storage in AWS. The function 
processes three main types of CloudFormation operations: Create, Update, and Delete. 
During creation, it generates a new EC2 key pair and immediately stores its private key 
material in AWS Systems Manager Parameter Store as an encrypted SecureString parameter. 
For updates, the function handles the transition between old and new resources by first 
removing the existing key pair, then creating a new one with the updated configuration, 
and finally updating the corresponding Parameter Store entry. During deletion, it performs 
cleanup by removing both the EC2 key pair and its associated Parameter Store parameter. 
The code is structured to ensure secure management of key pairs while maintaining 
accessibility to the private keys through AWS's secure parameter storage service. 
'''

# Import required AWS SDK and standard libraries
import boto3
import json
import os

def lambda_handler(event, context):
    # Initialize AWS service clients
    ec2 = boto3.client('ec2')
    ssm = boto3.client('ssm')

    # Extract important values from the CloudFormation custom resource event
    request_type = event['RequestType'] # Type of CloudFormation operation (Create/Update/Delete)
    properties = event['ResourceProperties'] # Resource properties from CloudFormation template
    key_pair_name = properties['KeyPairName'] # Name for the EC2 key pair
    parameter_name = properties['ParameterName'] # Name for SSM Parameter Store entry
    
    try:
        # Handle resource creation
        if request_type == 'Create':
            # Create the key pair and immediately capture the private key
            key_pair = ec2.create_key_pair(KeyName=key_pair_name)
            private_key = key_pair['KeyMaterial'] # Extract the private key
            
            # Store the private key securely in SSM Parameter Store
            ssm.put_parameter(
                Name=parameter_name,
                Value=private_key,
                Type='SecureString', # Encrypts the parameter value
                Overwrite=True # Overwrites if parameter already exists
            )

            # Return success response with resource details
            return {
                'PhysicalResourceId': key_pair_name,
                'Data': {
                    'KeyName': key_pair_name,
                    'ParameterName': parameter_name
                }
            }

        # Handle resource deletion    
        elif request_type == 'Delete':
            # Attempt to clean up both key pair and parameter
            try:
                ec2.delete_key_pair(KeyName=key_pair_name)
                ssm.delete_parameter(Name=parameter_name)
            except Exception as e:
                print(f"Error during deletion: {str(e)}")

            # Return success response
            return {
                'PhysicalResourceId': key_pair_name
            }
            
        # Handle resource updates    
        elif request_type == 'Update':
            # Get the name of the existing key pair
            old_key_name = event['PhysicalResourceId']
            
            # Attempt to delete the old key pair
            try:
                ec2.delete_key_pair(KeyName=old_key_name)
            except:
                pass # Ignore if old key pair doesn't exist
                
            # Create new key pair with updated name
            key_pair = ec2.create_key_pair(KeyName=key_pair_name)
            private_key = key_pair['KeyMaterial']
            
            # Update the parameter store with new private key
            ssm.put_parameter(
                Name=parameter_name,
                Value=private_key,
                Type='SecureString',
                Overwrite=True
            )
            
            # Return success response with updated resource details
            return {
                'PhysicalResourceId': key_pair_name,
                'Data': {
                    'KeyName': key_pair_name,
                    'ParameterName': parameter_name
                }
            }
            
    except Exception as e:
        # Log any errors and re-raise them
        print(e)
        raise e
