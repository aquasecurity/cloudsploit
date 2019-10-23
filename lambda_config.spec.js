var configs = require('./lambda_config.js')
var expect = require('chai').expect;

//Put events into JSON files...
var sns_event = {
    "Records": [
        {
            "EventSource": "aws:sns",
            "EventVersion": "1.0",
            "EventSubscriptionArn": "arn:aws:sns:us-east-1:{{{accountId}}}:ExampleTopic",
            "Sns": {
                "Type": "Notification",
                "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:ExampleTopic",
                "Subject": "example subject",
                "Message": "{\"aws\" : {\"roleArn\": \"arn:aws:iam::1234567890:role/someRole\"}}",
                "Timestamp": "1970-01-01T00:00:00.000Z",
                "SignatureVersion": "1",
                "Signature": "EXAMPLE",
                "SigningCertUrl": "EXAMPLE",
                "UnsubscribeUrl": "EXAMPLE",
                "MessageAttributes": {
                    "Test": {
                        "Type": "String",
                        "Value": "TestString"
                    },
                    "TestBinary": {
                        "Type": "Binary",
                        "Value": "TestBinary"
                    }
                }
            }
        }
    ]
}

var cloudwatch_event = {
    "id": "cdc73f9d-aea9-11e3-9d5a-835b769c0d9c",
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "account": "{{{account-id}}}",
    "time": "1970-01-01T00:00:00Z",
    "region": "us-east-1",
    "resources": [
        "arn:aws:events:us-east-1:123456789012:rule/ExampleRule"
    ],
    "detail": {
        "aws": {
            "roleArn": "arn:aws:iam::1234567890:role/someRole"
        }
    }
}

var expected_outcome = {
    'aws': {
        "roleArn": "arn:aws:iam::1234567890:role/someRole"
    }
}

var config_with_account_id = {
    'aws': {
        "account_id": "1234567890"
    }
}

var expected_config_from_account_id = {
    'aws': {
        "roleArn": ("arn:aws:iam::1234567890:role/" + process.env.DEFAULT_ROLE_NAME)
    }
}

var not_credentialed_configuration = {
    "gcp" : {
        "private_key": ""
    }
}

var no_service_provided = {}

var multiple_services_provided = {
    'aws' : {},
    'gcp' : {}
}

describe('configs', () => {
    describe('parseEvent', () => {
        it('Gets JSON object from SNS event', () => {
            expect(configs.parseEvent(sns_event)).to.equal(expected_outcome)
        })
        it('Gets JSON object from CloudWatch event', () => {
            expect(configs.parseEvent(cloudwatch_event)).to.equal(expected_outcome)
        })
    })

    describe('getConfigurations', () => {
        var partition = "aws"
        it('Gets aws configurations from SNS with RoleArn', () => {
            expect(configs.getConfigurations(configs.parseEvent(sns_event), partition)).to.equal(expected_outcome)
        })
        it('Gets aws configurations from Cloudwatch with RoleArn', () => {
            expect(configs.getConfigurations(configs.parseEvent(cloudwatch_event), partition)).to.equal(expected_outcome)
        })
        it('Gets aws configurations contianing Account ID', () => {
            expect(configs.getConfigurations(config_with_account_id, partition)).to.equal(expected_config_from_account_id)
        })
        it('Should throw an error when given a key that must be credentialed', () => {
            expect(configs.getConfigurations(not_credentialed_configuration, partition)).to.throw("Configuration passed in through event which must be in Secrets Manager.")
        })
        it('Should throw an error when given a configuration without a valid service', () => {
            expect(configs.getConfigurations(no_service_provided, partition)).to.throw("No services provided or provided services are malformed in Incoming Event.")
        })
        it('Should throw an error when given a configuration with multiple services', () => {
            expect(configs.getConfigurations(multiple_services_provided, partition)).to.throw("Multiple Services in Incoming Event.")
        })
    })
})