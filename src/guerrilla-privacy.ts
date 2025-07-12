/*
Author: Daniel Chisner
Date: 2025 03 31
Summary: 
This Type Script creates the resources, policies, and backbone architecture for the Guerrilla 
Privacy application. See the architectural diagram to see how the components connect. 
*/
import * as cdk from 'aws-cdk-lib';
import { Duration, Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import { AppConfig } from "./utils/config";
import * as cr from 'aws-cdk-lib/custom-resources';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';  // Add this import
import {
    aws_sns as sns,
    aws_sqs as sqs,
    aws_s3 as s3,
    aws_sns_subscriptions as sns_subscriptions,
    aws_events as events,
    aws_events_targets as targets, 
    aws_iam as iam,
    aws_lambda as lambda,
    aws_lambda_destinations as destinations,
    aws_ssm as ssm,
    aws_s3_notifications as s3n,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    aws_cloudwatch as cloudwatch,
    aws_cloudtrail as cloudtrail,
    aws_kms as kms,
    aws_logs as logs,
    aws_logs_destinations as logs_destinations    
} from 'aws-cdk-lib';

export interface GuerrillaPrivacyStackProps extends cdk.StackProps {
    config: AppConfig;
}

export class GuerrillaPrivacyStack extends Stack {
    constructor(scope: cdk.App, id: string, props: GuerrillaPrivacyStackProps) {
        super(scope, id, props);
    
        //Create EC2 CloudWatch Role
        const ec2Role = new iam.Role(this, 'EC2CloudWatchRole', { 
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy'),
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')
            ]
        });

        // Automatically delete the bucket when the CDK stack is destroyed/removed 
        const instanceFlagsBucket = new s3.Bucket(this, 'InstanceFlagsBucket', {
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            autoDeleteObjects: true
        });

        /* 
        Create a scheduled queue that sends a message to lambda after 15 minutes
        (see #12 on architectural diagram). Message visibility times out after 2 minutes.
        */
        const scheduledQueue = new sqs.Queue(this, 'ScheduledQueue', {
            deliveryDelay: Duration.minutes(15),
            visibilityTimeout: Duration.minutes(2)  

        });
        
        // Create policy to allow logging from EC2 role
        ec2Role.addToPolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
                'logs:DescribeLogStreams',
                'logs:PutRetentionPolicy'
            ],
            resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:/ec2/rdp/connections:*`]
        }));        

        // Create the key pair function
        const createKeyPairFunction = new lambda.Function(this, 'CreateKeyPairFunction', {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'create_keypair.lambda_handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda')),
            timeout: Duration.seconds(300)
        });

        // Add necessary permissions for key pair function 
        // (allows a key pair for EC2 instances to be created and written to parameter store)
        createKeyPairFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'ec2:CreateKeyPair',
                'ec2:DeleteKeyPair',
                'ssm:PutParameter',
                'ssm:DeleteParameter'
            ],
            resources: ['*']
        }));
     
        // Create the provider (custom function) for key pair creation
        const createKeyPairProvider = new cr.Provider(this, 'CreateKeyPairProvider', {
            onEventHandler: createKeyPairFunction,
        });

        // The EC2 key pair is stored into parameter store under the /EC2/Keys/Guerrilla-Privacy/private-key parameter name
        const keyPair = new cdk.CustomResource(this, 'KeyPair', {
            serviceToken: createKeyPairProvider.serviceToken,
            properties: {
                KeyPairName: `${props.config.appName}-key-pair`,
                ParameterName: `/EC2/Keys/${props.config.appName}/private-key`
            }
        });

        // Create a KMS key for parameter encryption
        const parameterKey = new kms.Key(this, `ParameterKey-${props.config.appName}`, {
            enableKeyRotation: true,
            description: 'KMS key for EC2 password parameters',
            alias: `alias/${props.config.appName}-parameter-key`
        });

        // Create RSA Layer for password decryption
        const rsaLayer = new lambda.LayerVersion(this, 'RsaLayer', {
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda-layer/rsa-layer.zip')),
            compatibleRuntimes: [lambda.Runtime.PYTHON_3_9],
            description: 'Layer containing rsa package for Windows password decryption',
        });
        
        // Creates the passwordHandler lambda to retrieve passwords from newly created EC2s
        const passwordHandler = new lambda.Function(this, `PasswordHandler-${props.config.appName}`, {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'password_handler.lambda_handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda')),
            layers: [rsaLayer],  // Using RSA layer 
            timeout: Duration.seconds(300),
            environment: {
                KMS_KEY_ARN: parameterKey.keyArn,
                KEY_PAIR_PARAMETER_NAME: `/EC2/Keys/${props.config.appName}/private-key`
            }
        });
        
        //Add respective actions to passwordHandler role
        passwordHandler.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'ec2:DescribeInstances',
                'ec2:GetPasswordData',
                'ssm:PutParameter',
                'ssm:GetParameter',
                'autoscaling:DescribeAutoScalingGroups',
                'autoscaling:DescribeAutoScalingInstances',
                'autoscaling:CompleteLifecycleAction',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources: ['*']
        }));
        

        // Add additional permissions to describe auto scaling groups/instances to get passwords
        passwordHandler.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'autoscaling:DescribeAutoScalingGroups',
                'autoscaling:DescribeAutoScalingInstances',
                'ec2:DescribeInstances'
            ],
            resources: ['*']
        }));

        // Grant the Lambda function permissions to encrypt/decrypt parameters
        parameterKey.grantEncrypt(passwordHandler);
        parameterKey.grantDecrypt(passwordHandler);

        // Create VPC with 2 AZs
        const vpc = new ec2.Vpc(this, `VPC-${props.config.appName}`, {
            maxAzs: 2
        });

        // Create a NLB that is internet facing and allows cross zone routing to the different auto scaling groups
        const nlb = new elbv2.NetworkLoadBalancer(this, `RDP-NLB-${props.config.appName}`, {
            vpc,
            internetFacing: true,
            crossZoneEnabled: true,
            vpcSubnets: {
                subnetType: ec2.SubnetType.PUBLIC
            },
        });

        // Create EC2 security group
        const instanceSG = new ec2.SecurityGroup(this, `RDP-Instance-SG-${props.config.appName}`, {
            vpc,
            description: 'Security group for RDP instances',
            allowAllOutbound: true,
        });

        //YOU MUST FIX THE IPV4 IP ADDRESS BEFORE DEPLOYING. SET IT TO YOUR CURRENT IP FOR YOUR CLIENT DEVICE. 
        //THIS ENABLES YOU TO RDP TO THE NLB AND BE ROUTED TO THE BACKEND EC2. 
        //DO NOT SET THIS VALUE TO 0.0.0.0/0 
        instanceSG.addIngressRule(
            ec2.Peer.ipv4('X.X.X.X/28'), //UPDATE THE IP ADDRESS
            ec2.Port.tcp(3389),
            'Allow RDP only from within VPC (NLB)'
        );

        // Create target group with health checks conducted over RDP. Healthy/unhealthy threshold is 2 and 
        // health checks are conducted every 30 seconds
        const targetGroup = new elbv2.NetworkTargetGroup(this, `RDP-TargetGroup-${props.config.appName}`, {
            vpc,
            port: 3389,
            protocol: elbv2.Protocol.TCP,
            targetType: elbv2.TargetType.INSTANCE,
            preserveClientIp: true, // This enables sticky sessions by source IP
            healthCheck: {
                enabled: true,
                port: '3389',
                protocol: elbv2.Protocol.TCP,
                healthyThresholdCount: 2,
                unhealthyThresholdCount: 2,
                timeout: Duration.seconds(10),
                interval: Duration.seconds(30),
            }
        });

        // Add listener on RDP for NLB
        const listener = nlb.addListener(`RDPListener-${props.config.appName}`, {
            port: 3389,
            protocol: elbv2.Protocol.TCP,
            defaultTargetGroups: [targetGroup],
        });

        // Adds stickiness to the NLB to keep browsing session for 15 minutes until termination. 
        const cfnTargetGroup = targetGroup.node.defaultChild as elbv2.CfnTargetGroup;
        cfnTargetGroup.addPropertyOverride('TargetGroupAttributes', [
            {
                Key: 'stickiness.enabled',
                Value: 'true'
            },
            {
                Key: 'stickiness.type',
                Value: 'source_ip'
            }
        ]);

        // Create Autoscaling group with min, max, and desired capacity of 2. This will keep 2 Windows VMs being created. 
        const asg = new autoscaling.AutoScalingGroup(this, `RDP-ASG-${props.config.appName}`, {
            vpc,
            vpcSubnets: {
                subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
            },
            instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machineImage: new ec2.WindowsImage(ec2.WindowsVersion.WINDOWS_SERVER_2022_ENGLISH_FULL_BASE),
            minCapacity: 2,
            maxCapacity: 2,
            desiredCapacity: 2,
            securityGroup: instanceSG,
            keyName: `${props.config.appName}-key-pair`,
            role: ec2Role  
        });

        // Create flow log role
        const flowLogRole = new iam.Role(this, 'FlowLogRole', {
            assumedBy: new iam.ServicePrincipal('vpc-flow-logs.amazonaws.com')
        });

        // Network flow logs are stored in CloudWatch under log group, "/vpc/nlb-connections"
        // Logs are deleted after a day (lowest retention time) to save on cost
        const flowLogGroup = new logs.LogGroup(this, 'NLBConnectionLogs', {
            logGroupName: '/vpc/nlb-connections',
            retention: logs.RetentionDays.ONE_DAY
        });

        // Allow flowLogRole to write to flowLogGroup
        flowLogGroup.grantWrite(flowLogRole);

        // Log flow logs of EC2/NLB
        new ec2.FlowLog(this, 'NLBFlowLog', {
            resourceType: ec2.FlowLogResourceType.fromVpc(vpc),
            destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogGroup),
            trafficType: ec2.FlowLogTrafficType.ALL,
        });

        // Add SNS topic for notifications (sends EC2 you connect to and the password for the instance so RDP connection can be authenticated)
        const connectionNotificationTopic = new sns.Topic(this, 'ConnectionNotifications');

        // UPDATE WITH YOUR EMAIL. THIS ALLOWS THE EC2 PASSWORDS TO BE SENT TO YOUR EMAIL. 
        connectionNotificationTopic.addSubscription(
            new sns_subscriptions.EmailSubscription('email@email.com')
        );

        // Add Lambda function to process flow logs
        const connectionTrackerFunction = new lambda.Function(this, 'ConnectionTrackerFunction', {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'index.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/connection-tracker')),
            timeout: Duration.minutes(1),
            environment: {
                VPC_ID: vpc.vpcId,
                NLB_DNS: nlb.loadBalancerDnsName,
                SNS_TOPIC_ARN: connectionNotificationTopic.topicArn,
                INSTANCE_FLAGS_BUCKET: instanceFlagsBucket.bucketName, // Allows creation of objects in instanceFlagsBucket (s3 bucket)
                QUEUE_URL: scheduledQueue.queueUrl,
            },
            logRetention: logs.RetentionDays.ONE_WEEK  // Keep Lambda logs for 1 week
        });

        // Grant queue permissions
        scheduledQueue.grantSendMessages(connectionTrackerFunction);

        // Grant connectionTrackerFunction general IAM policies
        connectionTrackerFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'logs:GetLogEvents',
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
                'ec2:DescribeInstances',
                'ec2:DescribeNetworkInterfaces',
                'elasticloadbalancing:DescribeLoadBalancers',
                'elasticloadbalancing:DescribeTargetHealth',
                'sns:Publish'
            ],
            resources: ['*']
        }));

        // SSM Parameter access
        connectionTrackerFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'ssm:GetParameter',
                'ssm:GetParameters'
            ],
            resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter/EC2/Passwords/*`]
        }));

        // KMS decrypt access
        connectionTrackerFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['kms:Decrypt'],
            resources: [`arn:aws:kms:${this.region}:${this.account}:alias/guerrilla-privacy-parameter-key`]
        }));

        // Grant read access to the instanceFlagsBucket (S3 bucket) for connectionTrackerFunction (lambda)
        instanceFlagsBucket.grantReadWrite(connectionTrackerFunction);

        // Gets the network interfaces for the EC2s
        const getNLBEnisFunction = new lambda.Function(this, 'GetNLBEnis', {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'get_nlb_enis.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda')),
            timeout: Duration.minutes(1),
            initialPolicy: [
                new iam.PolicyStatement({
                    actions: ['ec2:DescribeNetworkInterfaces'],
                    resources: ['*']
                })
            ]
        });

        // Create a subscription filter for the flow logs that looks for public IPs 
        new logs.SubscriptionFilter(this, 'FlowLogSubscription', {
            logGroup: flowLogGroup,
            destination: new logs_destinations.LambdaDestination(connectionTrackerFunction),
            filterPattern: logs.FilterPattern.literal(
                '[version, account, interface, ' +
                'srcaddr, (dstaddr != "10.*" && dstaddr != "172.16.*" && dstaddr != "192.168.*"), ' +
                'dstport = 3389, srcport, protocol = 6, packets, bytes, start, end, ' +
                'action = "ACCEPT", log_status = "OK"]'
            )
        });

        // Add CloudWatch Dashboard to monitor RDP connections
        const dashboard = new cloudwatch.Dashboard(this, 'RDPConnectionsDashboard', {
            dashboardName: 'RDP-Connections'
        });

        // Invoke connectionTrackerFunction when filter is met
        connectionTrackerFunction.addPermission('CloudWatchLogsInvocation', {
            principal: new iam.ServicePrincipal('logs.amazonaws.com'),
            action: 'lambda:InvokeFunction',
            sourceArn: `arn:aws:logs:${this.region}:${this.account}:log-group:${flowLogGroup.logGroupName}:*`
        });

        targetGroup.addTarget(asg); //create target to target group 

        // Allow RDP traffic from NLB to EC2
        instanceSG.addIngressRule(
            ec2.Peer.ipv4(vpc.vpcCidrBlock),
            ec2.Port.tcp(3389),
            'Allow RDP from NLB'
        );

        // Monitor for EC2 launch event (new EC2 was created)
        const rule = new events.Rule(this, `ASG-Launch-Rule-${props.config.appName}`, {
            description: 'Monitor EC2 launches from Auto Scaling group',
            eventPattern: {
                source: ['aws.autoscaling'],
                detailType: [
                    'EC2 Instance Launch Successful',
                    'EC2 Instance-launch Lifecycle Action',
                    'Auto Scaling Instance Launch Successful'
                ],
                detail: {
                    AutoScalingGroupName: [asg.autoScalingGroupName]
                }
            }
        });

        // Add Lambda invocation permission for EventBridge
        passwordHandler.addPermission('EventBridgeInvocation', {
            principal: new iam.ServicePrincipal('events.amazonaws.com'),
            action: 'lambda:InvokeFunction',
            sourceArn: rule.ruleArn
        });

        // Add the target with retry policy and dead letter queue
        rule.addTarget(new targets.LambdaFunction(passwordHandler, {
            retryAttempts: 3,
            maxEventAge: Duration.hours(2)
        }));

        // Scale down the EC2 auto scaling group 0 EC2s and then up to 2 
        const scaleDownLambda = new lambda.Function(this, 'ScaleDownFunction', {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'scale_down.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda')),
            timeout: Duration.minutes(5)
        });
        
        // Add permissions for scaleDownLambda lambda
        scaleDownLambda.addToRolePolicy(new iam.PolicyStatement({
            actions: ['autoscaling:UpdateAutoScalingGroup'],
            resources: ['*']
        }));
        
        // Create Custom Resource for trigger of scale down
        const scaleDownTrigger = new cdk.CustomResource(this, 'ScaleDownTrigger', {
            serviceToken: new cr.Provider(this, 'ScaleDownProvider', {
                onEventHandler: scaleDownLambda
            }).serviceToken,
            properties: {
                asgName: asg.autoScalingGroupName,
                timestamp: Date.now()
            }
        });

        // Add policies to flowLogRole
        flowLogRole.addToPolicy(new iam.PolicyStatement({
            actions: [
                'logs:CreateLogStream',
                'logs:PutLogEvents',
                'lambda:InvokeFunction'  
            ],
            resources: [
                flowLogGroup.logGroupArn,
                connectionTrackerFunction.functionArn  
            ]
        }));
        
        // Add dependency
        scaleDownTrigger.node.addDependency(asg);    
        
        // Create Lambda that processes SQS messages and terminates EC2
        const sqsProcessorFunction = new lambda.Function(this, 'SQSProcessorFunction', {
            runtime: lambda.Runtime.PYTHON_3_9,
            handler: 'index.handler',
            code: lambda.Code.fromAsset(path.join(__dirname, 'lambda/sqs-processor')),
            timeout: Duration.minutes(1),
            environment: {
                VPC_ID: vpc.vpcId,
                INSTANCE_FLAGS_BUCKET: instanceFlagsBucket.bucketName
            }
        });

        // Add EC2 termination permissions to the Lambda
        sqsProcessorFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'ec2:TerminateInstances',
                'ec2:StopInstances',
                'ec2:DescribeInstances'
            ],
            resources: ['*']
        }));

        // Allow sqsProcessorFunction to delete Parameter for EC2 from Parameter Store
        sqsProcessorFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                'ssm:DeleteParameter',
                'ssm:GetParameter'
            ],
            resources: [
                `arn:aws:ssm:${process.env.CDK_DEFAULT_REGION}:${process.env.CDK_DEFAULT_ACCOUNT}:parameter/EC2/Passwords/*`
            ]
        }));

        instanceFlagsBucket.grantReadWrite(sqsProcessorFunction);

        // Add specific S3 permissions including delete
        sqsProcessorFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: [
                's3:GetObject',
                's3:DeleteObject',
                's3:ListBucket'
            ],
            resources: [
                instanceFlagsBucket.bucketArn,
                `${instanceFlagsBucket.bucketArn}/*`
            ]
        }));

        // Add SQS as event source for Lambda
        sqsProcessorFunction.addEventSource(new SqsEventSource(scheduledQueue, {
            batchSize: 1,  // Process one message at a time
            enabled: true
        }));

        // Grant permissions for sqsProcessFunction to post to scheduledQueue
        scheduledQueue.grantConsumeMessages(sqsProcessorFunction);

        // Output EC2 keys as /EC2/Keys/${props.config.appName}/windows-password
        new cdk.CfnOutput(this, `ParameterName-${props.config.appName}`, {
            value: `/EC2/Keys/${props.config.appName}/windows-password`,
            description: 'SSM Parameter name for Windows password'
        });

        new cdk.CfnOutput(this, `KMSKeyArn-${props.config.appName}`, {
            value: parameterKey.keyArn,
            description: 'KMS Key ARN'
        });

        // Add output for SNS topic ARN
        new cdk.CfnOutput(this, 'ConnectionNotificationTopicArn', {
            value: connectionNotificationTopic.topicArn,
            description: 'SNS Topic ARN for connection notifications'
        });

        new cdk.CfnOutput(this, `LoadBalancerDNS-${props.config.appName}`, {
            value: nlb.loadBalancerDnsName,
            description: 'Network Load Balancer DNS Name'
        });

        new cdk.CfnOutput(this, `KeyPairName-${props.config.appName}`, {
            value: keyPair.getAttString('KeyName'),
            description: 'EC2 Key Pair Name'
        });
    }
}
