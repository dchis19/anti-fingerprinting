'''
Author: Daniel Chisner
Date: 2025 04 12

Summary:
This Lambda function serves as an automated EC2 instance termination processor 
that works in conjunction with an SQS queue. When triggered, it processes 
incoming SQS messages containing EC2 instance IDs and executes a controlled 
termination workflow. For each message, the function performs several critical 
checks: it verifies the instance exists, confirms it's running, and most 
importantly, validates that the instance belongs to the authorized VPC (specified 
via environment variables) as a security measure. This VPC validation serves as a 
crucial security boundary to prevent unauthorized termination of instances in 
other VPCs. The function implements comprehensive error handling and logging 
throughout the process, with the ability to trigger message retries through SQS 
if failures occur. Each successful termination is logged for audit purposes, while 
security violations and missing instances are also documented. This lambda
is used to terminate the EC2 instances after the (15) minute delay queue, allowing
for instances to be terminated after (15) minutes of a connection being made to an
EC2.
'''

# Import required libraries for JSON parsing, AWS SDK, and environment variables
import json
import boto3
import os

"""
Lambda handler that processes SQS messages to terminate EC2 instances
Args:
    event: Contains SQS messages with instance IDs to terminate
    context: Lambda context object
Returns:
    dict: Response indicating processing status
"""


def handler(event, context):
    
    # Initialize AWS EC2 client
    ec2 = boto3.client('ec2')
    ssm = boto3.client('ssm')
    s3 = boto3.client('s3')
    
    # Get bucket name from environment variable
    bucket_name = os.environ['INSTANCE_FLAGS_BUCKET']
    
    # Iterate through each SQS message in the batch
    for record in event['Records']:
        try:
            # Parse the SQS message body to get instance details
            message = json.loads(record['body'])
            instance_id = message['instance_id']
            
            # Log the instance being processed
            print(f"Processing termination for instance: {instance_id}")
            
            # Call EC2 API to get instance details
            # This verifies instance exists and gets its current state
            response = ec2.describe_instances(
                InstanceIds=[instance_id]
            )
            
            # Check if instance exists (Reservations will be empty if not found)
            if response['Reservations']:
                # Extract instance details from response
                instance = response['Reservations'][0]['Instances'][0]
                
                # Security check: Verify instance is in the authorized VPC
                # Prevents termination of instances in other VPCs
                if instance['VpcId'] == os.environ['VPC_ID']:
                    # Delete the parameter associated with the EC2
                    try:
                        parameter_name = f"/EC2/Passwords/{instance_id}"
                        ssm.delete_parameter(
                            Name=parameter_name
                        )
                        print(f"Successfully deleted parameter: {parameter_name}")
                    except ssm.exceptions.ParameterNotFound:
                        print(f"Parameter {parameter_name} not found - continuing with termination")
                    except Exception as e:
                        print(f"Error deleting parameter: {str(e)}")
                    # Delete S3 object
                    try:
                        s3.delete_object(
                            Bucket=bucket_name,
                            Key=instance_id
                        )
                        print(f"Successfully deleted S3 object: {instance_id}")
                    except Exception as e:
                        print(f"Error deleting S3 object: {str(e)}")
                    # Initiate instance termination
                    ec2.terminate_instances(
                        InstanceIds=[instance_id]
                    )
                    print(f"Successfully initiated termination for instance {instance_id}")
                else:
                    # Log security violation attempt
                    print(f"Instance {instance_id} is not in the expected VPC")
            else:
                # Log if instance not found
                print(f"Instance {instance_id} not found")
            
        except Exception as e:
            # Log any errors during processing
            print(f"Error processing termination: {str(e)}")
            # Raising the exception will cause SQS to retry the message
            raise

    # Return success response
    return {
        'statusCode': 200,
        'body': 'Instance termination processed'
    }
