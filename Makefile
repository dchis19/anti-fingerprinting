.DEFAULT_GOAL := deploy-all
include make-env

# Deploy the CDK2 bootstrap CloudFormation stack for a given AWS region
deploy-cdk2-bootstrap-cf-stack:
	@echo "Bootstrapping cdk for AWS region: $(AWS_REGION)"
	(AWS_REGION=$(AWS_REGION) cdk bootstrap)
	@echo "Bootstrapping cdk for AWS region $(AWS_REGION) completed successfully !"

# Destroy the CDK2 bootstrap CloudFormation stack
destroy-cdk2-bootstrap-cf-stack:
	@echo "Delete cdk Bootstrap"
	aws cloudformation delete-stack \
	--stack-name CDKToolkit
	aws cloudformation wait stack-delete-complete \
	--stack-name CDKToolkit
	@echo "Delete cdk Bootstrap completed successfully"

# Deploy infrastructure using CDK
deploy-infra:
	@echo "Deploying Infrastructure"
	(node_modules/aws-cdk/bin/cdk diff --all; \
		node_modules/aws-cdk/bin/cdk deploy --all --require-approval never)
	@echo "Finished Deploying Infrastructure"

# Destroy infrastructure using CDK
destroy-infra:
	@echo "Destroying Infrastructure"
	(node_modules/aws-cdk/bin/cdk destroy --all --force)
	@echo "Finished Destroying Infrastructure"

# Deploy all steps: Push configurations and deploy infrastructure
deploy-all: deploy-infra

# Destroy all steps: Destroy infrastructure
destroy-all: destroy-infra
