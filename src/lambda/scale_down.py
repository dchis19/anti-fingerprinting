'''
Author: Daniel Chisner
Date: 2025 04 12

Summary: 
This Lambda function serves as a CloudFormation custom resource handler designed 
to perform a controlled instance refresh in an Auto Scaling Group (ASG). When 
triggered by Create or Update events from CloudFormation, the function executes 
a sequence of scaling operations to replace all instances in the specified ASG. 
It first waits for 2 minutes to ensure any existing instances are fully initialized, 
then scales the ASG down to zero instances, effectively terminating all running 
instances. After waiting an additional minute for the terminations to complete, it 
scales the ASG back up to two instances, resulting in fresh instance launches. This
allows the EC2 Windows passwords to be written into Parameter Store. This is a one time 
event during infrastructure creation. The function implements deliberate waiting 
periods to maintain stability during the transition and returns a success response 
to CloudFormation upon completion. This approach provides an automated way to perform 
instance refreshes as part of infrastructure deployments or updates.
'''

# Import required AWS SDK and utility libraries
import boto3
import time
import json

"""
Lambda handler to manage Auto Scaling Group capacity cycling
Args:
    event: CloudFormation custom resource event
    context: Lambda context object
Returns:
    dict: Response indicating operation status
"""

def handler(event, context):
    
    # Log the incoming event for debugging
    print('Event:', json.dumps(event))
    
    # Process only Create or Update events, ignore Delete
    if event.get('RequestType') in ['Create', 'Update']:

        # Initialize AWS Auto Scaling client
        autoscaling = boto3.client('autoscaling')

        # Get Auto Scaling Group name from the event properties
        asg_name = event['ResourceProperties']['asgName']
        
        # Wait for initial instances to fully initialize
        # This delay ensures instances are ready before scaling operations
        print('Waiting for 2 minutes to ensure instances are ready...')

        time.sleep(120) # 120 seconds = 2 minutes
        
        # Scale down ASG to 0 instances
        # This effectively terminates all running instances
        print('Scaling down to 0...')
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0
        )
        
        # Wait for instance termination to complete
        # This ensures all instances are fully terminated before scaling up
        print('Waiting 60 seconds for instances to terminate...')
        time.sleep(60) # 60 seconds = 1 minute
        
        # Scale back up to 2 instances
        # This launches fresh instances with any updated configurations
        print('Scaling back up to 2...')
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            MinSize=2,
            MaxSize=2,
            DesiredCapacity=2
        )
    
    # Return success response
    # PhysicalResourceId is required for CloudFormation custom resources
    return {
        'PhysicalResourceId': 'ScaleDownComplete',
        'Status': 'SUCCESS'
    }
