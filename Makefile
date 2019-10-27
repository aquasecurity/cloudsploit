
ifndef env
# $(error env is not set)
	env ?= dev
endif

ifdef CONFIG
	include $(CONFIG)
	export
else
	include config.$(env)
	export
endif

ifndef STACK_NAME
$(error STACK_NAME is not set)
endif

.PHONY: $(FUNCTIONS)

# # Run all tests
# test: cfn-validate
# 	cd lambda && $(MAKE) test

# # Do everything
# clean:
# 	cd lambda && $(MAKE) clean

build:
	npm install
	# because for some reason, the node modules were dated to 1985
	find ./node_modules/* -mtime +10950 -exec touch {} \;

package: build
	aws cloudformation package \
	  --s3-bucket ${ARTIFACT_BUCKET} \
	  --template-file ./cloudformation/template.yaml \
	  --output-template-file ./template.packaged.yaml

deploy: package
	aws cloudformation deploy \
	  --template-file ./template.packaged.yaml \
	  --capabilities CAPABILITY_IAM \
	  --no-fail-on-empty-changeset \
	  --stack-name ${STACK_NAME} \
	  --parameter-overrides \
	    DefaultRoleName=${DEFAULT_ROLE_NAME} \
	    SecretsManagerPrefix=${SECRETS_MANAGER_PREFIX} \
	    BucketName=${BUCKET_NAME} \
	    BucketPrefix=${BUCKET_PREFIX} \
	    CreateBucket=${CREATE_BUCKET} \
	    SNSTopic=${SNS_TOPIC} \
	    Schedule=${SCHEDULE} \
	    ScheduledAccountId=${SCHEDULED_ACCOUNT_ID} \
	    ScheduledRoleName=${SCHEDULED_ROLE_NAME} \
	    ScheduledExternalId=${SCHEDULED_EXTERNAL_ID}

sync-scorecards:
	aws s3 sync s3://$(BUCKET_NAME)/$(BUCKET_PREFIX) Results/$(STACK_NAME)
	open Results/$(STACK_NAME)
