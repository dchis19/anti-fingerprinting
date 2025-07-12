'''
Author: Daniel Chisner
Date: 2025 04 10

Summary:
This Lambda function serves as a RDP (Remote Desktop Protocol) connection monitoring 
and notification system within AWS environments. Upon receiving CloudWatch log events, 
the function processes and decodes network traffic information, specifically focusing 
on RDP connection attempts. It filters out Network Load Balancer (NLB) related traffic 
to prevent duplicate processing and maintains a tracking system for EC2 instances 
involved in these connections. The script maps source IP addresses to specific EC2 
instances and validates these connections against a designated VPC, while maintaining 
a record of processed instances in S3 to avoid redundant handling. For each valid 
connection, the function retrieves instance passwords from AWS Systems Manager Parameter 
Store and packages this information with detailed connection metadata, including timestamps, 
IP addresses, instance IDs, and network interface information. This compiled information 
is then distributed through two channels: an SNS topic for immediate notifications and 
an SQS queue for further processing. Throughout its operation, the function implements 
robust error handling and logging mechanisms, providing appropriate status codes (200, 
404, 500) based on the operation's outcome. 
'''

import json
import boto3
import os
from datetime import datetime
import base64
import zlib

# Custom JSON encoder class to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# Function to get Network Load Balancer (NLB) Elastic Network Interfaces (ENIs)
def get_nlb_enis():
    try:
        ec2 = boto3.client('ec2')
         # Query EC2 for network interfaces that belong to NLBs
        response = ec2.describe_network_interfaces(
            Filters=[{
                'Name': 'description',
                'Values': ['ELB net/*']
            }]
        )
        # Extract ENI IDs from the response
        eni_ids = [eni['NetworkInterfaceId'] for eni in response['NetworkInterfaces']]
        print(f"Found NLB ENIs: {eni_ids}")
        return eni_ids
    except Exception as e:
        print(f"Error getting NLB ENIs: {str(e)}")
        return []

# Main Lambda handler function
def handler(event, context):
    print(f"Received event: {json.dumps(event, cls=DateTimeEncoder)}")
    
    # Initialize AWS service clients
    ec2 = boto3.client('ec2')
    elbv2 = boto3.client('elbv2')
    sns = boto3.client('sns')

    # Get list of NLB ENIs to filter out
    nlb_enis = get_nlb_enis()
    
    try:
        # Handle CloudWatch Logs input (decompress if needed)
        if 'awslogs' in event:
            compressed_payload = base64.b64decode(event['awslogs']['data'])
            uncompressed_payload = zlib.decompress(compressed_payload, 16+zlib.MAX_WBITS)
            payload = json.loads(uncompressed_payload)
            log_events = payload['logEvents']
        else:
            log_events = event.get('logEvents', [])

        # Process each log event
        for log_event in log_events:
            try:
                print(f"Processing log event: {json.dumps(log_event, cls=DateTimeEncoder)}")

                # Parse the message fields
                message = log_event.get('message', '')
                fields = message.split()
                
                print(f"Fields parsed: {fields}")

                # Validate message format
                if len(fields) < 13:
                    print(f"Skipping log event - insufficient fields: {len(fields)}")
                    break

                # Skip NLB-related events
                interface_id = fields[2]
                if interface_id in nlb_enis:
                    print(f"Skipping NLB ENI: {interface_id}")
                    break

                # Extract relevant fields from the log message
                src_addr = fields[3]
                dst_addr = fields[4]
                dst_port = fields[6]
                action = fields[11]
                
                print(f"Parsed values - src: {src_addr}, dst: {dst_addr}, port: {dst_port}, action: {action}")

                # Look up EC2 instance details based on source IP
                response = ec2.describe_instances(
                    Filters=[
                        {
                            'Name': 'private-ip-address',
                            'Values': [src_addr]
                        },
                        {
                            'Name': 'vpc-id',
                            'Values': [os.environ['VPC_ID']]
                        }
                    ]
                )
                
                print(f"EC2 response: {json.dumps(response, cls=DateTimeEncoder)}")

                # Process instance information if found
                if response['Reservations'] and response['Reservations'][0]['Instances']:
                    instance = response['Reservations'][0]['Instances'][0]
                    instance_id = instance['InstanceId']

                    # Check if instance flag exists in S3
                    s3 = boto3.client('s3')
                    try:
                        s3.get_object(
                            Bucket=os.environ['INSTANCE_FLAGS_BUCKET'],
                            Key=instance_id
                        )
                        print(f"Instance {instance_id} already processed, skipping...")
                        return {
                            'statusCode': 200,
                            'body': json.dumps({'message': 'Instance already processed'})
                        }
                    
                    except s3.exceptions.NoSuchKey:
                        # Prepare connection information
                        connection_info = {
                            'timestamp': datetime.now().isoformat(),
                            'source_ip': src_addr,
                            'destination_ip': dst_addr,
                            'instance_id': instance_id,
                            'interface_id': interface_id,
                            'connection_type': 'RDP',
                            'nlb_dns': os.environ.get('NLB_DNS', 'Not provided'),
                            'vpc_id': os.environ.get('VPC_ID', 'Not provided')
                        }

                        # Create flag in S3 after successful SNS publish
                        s3.put_object(
                            Bucket=os.environ['INSTANCE_FLAGS_BUCKET'],
                            Key=instance_id,
                            Body=''  # Empty object, we just need the key to exist
                        )

                        print('SUCCESSFULLY PROCESSED CONNECTION INFO!!!')
    
                        # Get additional ENI information and instance password
                        eni_response = ec2.describe_network_interfaces(
                            NetworkInterfaceIds=[interface_id]
                        )
                        password = ''

                        # Retrieve instance password from SSM Parameter Store
                        if eni_response['NetworkInterfaces']:
                            eni_instance_id = eni_response['NetworkInterfaces'][0].get('Attachment', {}).get('InstanceId')
                            if eni_instance_id:
                                connection_info['eni_instance_id'] = eni_instance_id
                                
                                ssm = boto3.client('ssm')
                                try:
                                    password_response = ssm.get_parameter(
                                        Name=f'/EC2/Passwords/{eni_instance_id}',
                                        WithDecryption=True
                                    )
                                    instance_password = password_response['Parameter']['Value']
                                    connection_info['instance_password'] = instance_password
                                    password = instance_password
                                except ssm.exceptions.ParameterNotFound:
                                    print(f"No password found for instance {eni_instance_id}")
                                    connection_info['instance_password'] = 'Not found'
                                except Exception as e:
                                    print(f"Error retrieving password: {str(e)}")
                                    connection_info['instance_password'] = 'Error retrieving'

                        print(f'Your Password is {password}')

                        # Publish connection info to SNS
                        sns.publish(
                            TopicArn=os.environ['SNS_TOPIC_ARN'],
                            Subject='New RDP Connection Detected',
                            Message=json.dumps(connection_info, cls=DateTimeEncoder, indent=2)
                        )
                        
                        print(f"Successfully published connection info: {json.dumps(connection_info, cls=DateTimeEncoder)}")

                        # Send message to SQS queue
                        sqs = boto3.client('sqs')
                        sqs.send_message(
                            QueueUrl=os.environ['QUEUE_URL'],
                            MessageBody=json.dumps(connection_info),
                        )
                        
                        return {
                            'statusCode': 200,
                            'body': json.dumps(connection_info, cls=DateTimeEncoder)
                        }
                else:
                    print(f"No matching instance found for IP: {src_addr}")
                    
            except Exception as e:
                print(f"Error processing individual log event: {str(e)}")
                continue
        
        print("No matching RDP connections found in this batch")
        return {
            'statusCode': 404,
            'body': json.dumps({'message': 'No matching RDP connection found'}, cls=DateTimeEncoder)
        }
        
    except Exception as e:
        error_message = f"Error processing event: {str(e)}"
        print(error_message)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_message}, cls=DateTimeEncoder)
        }
