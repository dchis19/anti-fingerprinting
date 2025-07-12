'''
Author: Daniel Chisner
Date: 2025 04 12

Summary: This Lambda function is designed to retrieve Network Load Balancer (NLB) 
Elastic Network Interfaces (ENIs) from AWS EC2. The function primarily responds to 
CloudFormation Create or Update events, serving as a custom resource helper. When 
triggered, it uses the AWS SDK (boto3) to query EC2's network interfaces, 
specifically filtering for those with descriptions matching the pattern 'ELB net/*', 
which identifies NLB-associated ENIs. The function implements comprehensive error 
handling and logging to track its execution and any potential issues. Upon successful 
execution, it returns a comma-separated list of ENI IDs, or 'none' if no ENIs are 
found. In case of failure, it returns a 500 status code while maintaining a consistent 
response structure. The response includes a status code, a physical resource ID 
(derived from the Lambda's log stream name), and the ENI data. This function is used 
to track ENIs associated with the NLB. 
'''

# lambda/get_nlb_enis.py
# Import required AWS SDK and utility libraries
import boto3
import json
import urllib3
import logging

# Configure logging for the Lambda function
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    # Log the incoming event for debugging purposes
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Initialize default response structure
    response_data = {
        'Data': {
            'ENIs': 'none' # Default value if no ENIs are found
        }
    }
    
    try:
        # Only process Create or Update events
        if event['RequestType'] in ['Create', 'Update']:
            # Initialize AWS EC2 client
            ec2 = boto3.client('ec2')
            # Query EC2 to find network interfaces associated with NLB
            # Filter using description that matches NLB pattern
            response = ec2.describe_network_interfaces(
                Filters=[{
                    'Name': 'description',
                    'Values': ['ELB net/*'] # Pattern matching NLB ENIs
                }]
            )

            # Extract ENI IDs from the response
            eni_ids = [eni['NetworkInterfaceId'] for eni in response['NetworkInterfaces']]
            logger.info(f"Found ENIs: {eni_ids}")

            # Prepare response with found ENI IDs
            response_data = {
                'Data': {
                    # Join ENI IDs with comma or return 'none' if empty
                    'ENIs': ','.join(eni_ids) if eni_ids else 'none' 
                }
            }

        # Return successful response with ENI information
        return {
            'StatusCode': 200,
            'PhysicalResourceId': context.log_stream_name, # Use log stream as physical ID
            **response_data # Spread operator to include response data
        }
            
    except Exception as e:
        # Log any errors that occur during execution
        logger.error(f"Error: {str(e)}")
        # Return error response while maintaining response structure
        return {
            'StatusCode': 500,
            'PhysicalResourceId': context.log_stream_name,
            'Data': {
                'ENIs': 'none' # Return default value on error
            }
        }
