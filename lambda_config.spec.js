var configs = require('./lambda_config.js')
var chai = require('chai');
var chaiAsPromised = require("chai-as-promised")
var expect = require('chai').expect;
chai.use(chaiAsPromised)

//Put events into JSON files...
var snsEvent = {
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

var cloudwatchEvent = {
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

var expectedOutcome = {
    'aws': {
        "roleArn": "arn:aws:iam::1234567890:role/someRole"
    }
}

var configWithAccountId = {
    'aws': {
        "account_id": "1234567890"
    }
}

var expectedConfigFromAccountId = {
    'aws': {
        "roleArn": ("arn:aws:iam::1234567890:role/" + process.env.DEFAULT_ROLE_NAME)
    }
}

var notCredentialedConfiguration = {
    "gcp" : {
        "private_key": ""
    }
}

var noServiceProvided = {}

var multipleServicesProvided = {
    'aws' : {},
    'gcp' : {}
}

describe('configs', function () {
    describe('parseEvent', function () {
        it('Gets JSON object from SNS event', function () {
            expect(configs.parseEvent(snsEvent)).to.deep.equal(expectedOutcome)
        })
        it('Gets JSON object from CloudWatch event', function () {
            expect(configs.parseEvent(cloudwatchEvent)).to.deep.equal(expectedOutcome)
        })
    })

    describe('getConfigurations', function () {
        var partition = "aws"
        it('Gets aws configurations from SNS with RoleArn', async function () {
            var input = await configs.getConfigurations(configs.parseEvent(snsEvent), partition)
            var output = expectedOutcome
            expect(input).to.deep.equal(output)
        })
        it('Gets aws configurations from Cloudwatch with RoleArn', async function () {
            var input = await configs.getConfigurations(configs.parseEvent(cloudwatchEvent), partition)
            var output = expectedOutcome
            expect(input).to.deep.equal(output)
        })
        it('Gets aws configurations containing Account ID', async function () {
            var input = await configs.getConfigurations(configWithAccountId, partition)
            var output = expectedConfigFromAccountId
            expect(input).to.deep.equal(output)
        })
        it('Should throw an error when given a key that must be credentialed', async function () {
            var input = configs.getConfigurations(notCredentialedConfiguration, partition)
            expect(input).to.be.rejectedWith("Configuration passed in through event which must be in Secrets Manager.")
        })
        it('Should throw an error when given a configuration without a valid service', async function () {
            var input = configs.getConfigurations(noServiceProvided, partition)
            expect(input).to.be.rejectedWith("No services provided or provided services are malformed in Incoming Event.")
        })
        it('Should throw an error when given a configuration with multiple services', async function () {
            var input = configs.getConfigurations(multipleServicesProvided, partition)
            expect(input).to.be.rejectedWith("Multiple Services in Incoming Event.")
        })
        //need to find a way to test credentialedId.
    })
})